//! runtime event transport source guard.
//!
//! INVARIANT: EVENT-TRANSPORT-PG-INBOX-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::scan_content_rejects_missing_pg_bundle_fragment", anti_vacuity = "tests::scan_content_accepts_pg_inbox_bundle" }——
//! `assemblies/runtime/src/event_transport.rs` 的 consumer idempotency must come from PG inbox, not Redis,
//! and production consumer workers must go through the generated-topology bridge.
//! INVARIANT: EVENT-CONSUMER-EXTERNAL-EFFECT-POLICY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::scan_content_rejects_consumer_tx_plan_without_external_effect_policy", anti_vacuity = "tests::workspace_eventing_composition_shape_is_closed" }——
//! ConsumerTx plan 必须把 generated external-effect policy 纳入闭合 matcher；audit 仅接受
//! transactional-only，settings refresh 仅接受 reconcile，任何漂移都在启动前 fail-closed。
//! INVARIANT: EVENT-CONSUMER-RAW-EFFECT-CAPABILITY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::consumer_policy_guard_rejects_raw_effect_bypass_matrix", anti_vacuity = "tests::consumer_policy_guard_accepts_closed_capability_without_raw_effect" }——
//! policy-bound ConsumerTx handler 的 reachable production call graph 禁止绕过 capability 直接调用
//! publisher/HTTP/email/MDM/cloud/object-store；direct、function-item/import alias、UFCS、cross-file
//! helper、macro 与 chained request 均有 synthetic red，歧义 helper resolution fail closed。本 AST guard
//! 不声称具备编译器 HIR/宏展开完备性，assembly-private handler/runner 与 exact owner activation
//! 仍是主防线。
//! INVARIANT: EVENT-PRODUCER-GENERATED-EMIT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::producer_ast_rejects_raw_authoring_as_event_evidence|tests::producer_ast_rejects_multiple_generated_emit_specs_in_one_site", anti_vacuity = "tests::producer_ast_accepts_sealed_generated_emit_wrapper|tests::workspace_event_transport_and_active_producers_pass_guard" }——
//! active production event evidence comes exclusively from its generated per-event `emit` wrapper.
//! Raw `EventEntry`, envelope, SPEC aliases and handwritten helpers never contribute topology facts;
//! contract/envelope/partition matching remains inside the sealed generated encoder.
//! INVARIANT: OUTBOX-RELAY-CLAIM-CUTOVER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::outbox_claim_cutover_synthetic_red_rejects_legacy_production_paths", anti_vacuity = "tests::outbox_claim_cutover_accepts_canonical_and_non_production_bait" }——
//! production outbox relay providers, runtime wiring, eventexec dispatch, and post-cutover SQL must
//! remain on the single claimed-entry protocol; cross-crate/source-set completeness is enforced by
//! AST/SQL synthetic-red plus a canonical workspace green fixture.
//! INVARIANT: OUTBOX-RELAY-BUDGET-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::relay_budget_guard_synthetic_red_breaks_each_carrier", anti_vacuity = "tests::relay_budget_guard_accepts_canonical_workspace" }——
//! runtime typed config、AMQP 单 deadline、Postgres typed watchdog/settlement 与 0064 SQL 签名必须保持
//! 同一预算能力链；carrier 生产 Rust 禁止回流固定 40/50/60 秒 deadline。
//! INVARIANT: AMQP-PUBLISH-BYPASS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::amqp_publish_bypass_synthetic_red_rejects_direct_bypasses", anti_vacuity = "tests::amqp_publish_bypass_accepts_canonical_publisher" }——
//! production `impl Publisher for AmqpPublisher::publish`（含 reachable nested local callable，以及
//! live async/closure 内的敏感 call/macro/retirement；嵌套 callable 自己的 `?` 豁免）禁止直接构造
//! `PublisherError::{transient,permanent,ambiguous}`（含 bare import / type-alias call callee 末段）、
//! 直接 `retire_transport`、外层 `?` 或 macro 隐藏上述敏感调用；Hard owner 是 private closed
//! `PublishFailureDecision`/`DefinitivePublishKind`，provider behavior owner 是 budget/fencing/ambiguity
//! publish pipeline 行为（`OUTBOX-RELAY-BUDGET-01` 仍拥有 cross-language config/SQL/audit/hardcoded 与
//! 剩余 live seams）。
//! INVARIANT: AMQP-RSS-RECOVERY-OWNER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::relay_budget_guard_rejects_amqp_connection_auto_recovery_mutations", anti_vacuity = "tests::relay_budget_guard_accepts_amqp_connection_recovery_owner" }——
//! `conn.rs` 只能由 `connect_with_context` 使用 `ConnectionProperties::default()` 建立 Lapin connection；
//! 禁止 `enable_auto_recover` 或第二条 client-owned recovery path，publisher replacement 只归 RSS owner。
//! INVARIANT: PG-OUTBOX-SETTLEMENT-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::settlement_funnel_guard_synthetic_red_rejects_each_raw_function_and_query_path", anti_vacuity = "tests::settlement_funnel_guard_accepts_canonical_workspace" }——
//! production Rust 只能在私有 `outbox::settlement` 模块执行三个 raw settlement SQL
//! function；守卫以 Rust AST 中的 executable SQL call argument 识别调用，并要求私有模块持有
//! 三个 canonical execution witness，避免 comment/const/string bait 形成空门。
//! INVARIANT: EVENT-DEDICATED-RUNTIME-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::dedicated_runtime_funnel_rejects_production_builder", anti_vacuity = "tests::workspace_dedicated_runtime_funnel_is_closed" }——
//! production assembly 的 long-lived event worker 只能消费 `eventexec` 的 typed dedicated-runtime
//! factory；组合根不得重新构造 current-thread runtime，使 driver、build failure、health 与 completion
//! 始终由单一 lifecycle owner 收口。
//! INVARIANT: CONSUMER-SUBSCRIBE-SUPERVISE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::subscribe_supervise_rejects_one_shot_worker_exiting|tests::subscribe_supervise_rejects_definition_bait_without_spawn_call|tests::subscribe_supervise_rejects_missing_required_spawn|tests::subscribe_supervise_rejects_renamed_spawn", anti_vacuity = "tests::workspace_subscribe_supervise_is_closed" }——
//! ackable subscribe 生命周期必须经 `run_ackable_subscription_loop`（AST：spawn 生产函数体调用，非文件 contains）；每个
//! required spawn 必须跨 TARGETS 命中 ≥1；禁串只扫非 `#[doc]` 字符串字面量；禁止 subscribe 失败后
//! `worker exiting` one-shot 永久退出（#1605）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use quote::ToTokens;
use syn::parse::Parser as _;
use syn::spanned::Spanned as _;
use syn::visit::Visit;

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::{is_excluded, member_dirs, rs_files};
use crate::workspace_root;

const TARGET: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_LIB_TARGET: &str = "assemblies/runtime/src/lib.rs";
const RUNTIME_CONSUMER_TX_COMPAT_TARGET: &str = "assemblies/runtime/src/consumer_tx.rs";
const EVENTING_COMPOSITION_TARGET: &str = "composition/eventing/src/lib.rs";
const IDENTITYAUDIT_EVENTING_TARGET: &str = "assemblies/identityaudit/src/eventing.rs";
const RUNTIME_FORBIDDEN: &[&str] = &[
    "RedisInboxStore",
    "RSS_REDIS_CLAIM_TTL_MS",
    "redis_claim_ttl",
    "replaydeps::IdempotencyConfig",
    "redis idempotency",
    "Redis 幂等",
    "adapt_subscriber_handler",
    "spawn_consumer_ackable_subscriber(",
];
const RUNTIME_REDIS_INBOX_FRAGMENT: &str = "redis.infra().inbox(";
const DOMAIN_FORBIDDEN: &[&str] = &[
    "PgInboxStore",
    "RedisInboxStore",
    "ManagedBlockingWorker",
    "spawn_consumer(",
    "spawn_consumer_ackable(",
    "spawn_consumer_ackable_subscriber(",
    "pg.infra().inbox(",
    "pg.infra().dead_letter(",
];
const BYPASS_FORBIDDEN: &[&str] = &[
    "spawn_consumer(",
    "spawn_consumer_ackable(",
    "spawn_consumer_ackable_subscriber(",
    "spawn_consumer_ackable_tx_subscriber(",
    "pg.infra().inbox(",
];
const BYPASS_MEMBER_ROOTS: &[&str] = &["crates", "adapters", "assemblies", "bins"];
const BYPASS_LEAF_CRATES: &[&str] = &["journeys"];
const BYPASS_ALLOWED_PATHS: &[&str] = &[
    TARGET,
    "crates/eventexec/src/consumer_worker.rs",
    "adapters/postgres/src/bundle.rs",
    "adapters/postgres/src/inbox.rs",
    "adapters/redis/src/bundle.rs",
];
const POSTGRES_FAULT_MATRIX_HARNESS: &str = "adapters/postgres/src/fault_matrix.rs";
const POSTGRES_LIB_PATH: &str = "adapters/postgres/src/lib.rs";
const EVENT_CONTRACT_ROOT: &str = "contracts/event";
const DEDICATED_RUNTIME_ASSEMBLY_TARGETS: &[&str] = &[
    TARGET,
    IDENTITYAUDIT_EVENTING_TARGET,
    "assemblies/settingsonly/src/eventing.rs",
    "assemblies/settingsonly/src/dlx.rs",
];
const SUBSCRIBE_SUPERVISE_TARGETS: &[&str] = &[
    "crates/eventexec/src/consumer_worker.rs",
    "composition/eventing/src/consumer_tx.rs",
];
const SUBSCRIBE_SUPERVISE_REQUIRED: &str = "run_ackable_subscription_loop";
const SUBSCRIBE_SUPERVISE_FORBIDDEN: &str = "worker exiting";
const SUBSCRIBE_SUPERVISE_SPAWN_FNS: &[&str] = &[
    "spawn_consumer_ackable_subscriber",
    "spawn_consumer_ackable_tx_subscriber",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RedisConsumerClaimer,
    MissingBundleFragment,
    DomainConsumerBundleBypass,
    ProductionConsumerBundleBypass,
    ProducerTopology,
    OutboxClaimCutover,
    OutboxRelayBudget,
    AmqpPublishBypass,
    AmqpRecoveryOwner,
    PostgresOutboxSettlementFunnel,
    ConsumerExternalEffectCapability,
    DedicatedRuntimeFunnel,
    ConsumerSubscribeSupervise,
}

pub(crate) struct EventTransportGuard;

impl GovernanceCheck for EventTransportGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "event-transport-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        check_root(&root)
    }
}

/// Run the complete transport closure against an injected workspace root.
///
/// Assurance inventory generation consumes this API instead of maintaining a second AST parser.
pub(crate) fn check_root(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
    let path = root.join(TARGET);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
    let mut findings = scan_runtime_content(Path::new(TARGET), &content);
    let runtime_lib =
        std::fs::read_to_string(root.join(RUNTIME_LIB_TARGET)).with_context(|| {
            format!(
                "event-transport-guard: read {}",
                root.join(RUNTIME_LIB_TARGET).display()
            )
        })?;
    findings.extend(runtime_consumer_tx_compat_findings(
        &runtime_lib,
        root.join(RUNTIME_CONSUMER_TX_COMPAT_TARGET).exists(),
    ));
    let composition_path = root.join(EVENTING_COMPOSITION_TARGET);
    let composition_content = std::fs::read_to_string(&composition_path)
        .with_context(|| format!("event-transport-guard: read {}", composition_path.display()))?;
    findings.extend(scan_composition_content(
        Path::new(EVENTING_COMPOSITION_TARGET),
        &composition_content,
    ));
    let identityaudit_path = root.join(IDENTITYAUDIT_EVENTING_TARGET);
    if identityaudit_path.exists() {
        let identityaudit_content =
            std::fs::read_to_string(&identityaudit_path).with_context(|| {
                format!(
                    "event-transport-guard: read {}",
                    identityaudit_path.display()
                )
            })?;
        findings.extend(identityaudit_closure_findings(
            Path::new(IDENTITYAUDIT_EVENTING_TARGET),
            &identityaudit_content,
        ));
    }
    findings.extend(inbox_sampler_inventory_findings(root)?);
    findings.extend(scan_dedicated_runtime_sources(
        &load_dedicated_runtime_sources(root)?,
    ));
    findings.extend(scan_subscribe_supervise_sources(
        &load_subscribe_supervise_sources(root)?,
    ));
    findings.extend(scan_domain_crates(root)?);
    findings.extend(scan_production_bypasses(root)?);
    findings.extend(scan_event_producers(root)?);
    let claim_cutover_sources = load_outbox_claim_cutover_sources(root)?;
    findings.extend(scan_outbox_claim_cutover_sources(&claim_cutover_sources));
    findings.extend(scan_settlement_funnel_sources(&claim_cutover_sources).findings);
    let relay_budget_sources = load_relay_budget_sources(root)?;
    findings.extend(scan_relay_budget_sources(&relay_budget_sources));
    findings.extend(scan_relay_budget_constructor_callsites(
        &claim_cutover_sources,
    ));
    let (active_handler_count, consumer_policy_findings) =
        scan_consumer_external_effect_capabilities(root)?;
    findings.extend(consumer_policy_findings);
    Ok((
        format!(
            "{EVENTING_COMPOSITION_TARGET} 是 generated topology bridge + ConsumerTx 唯一真源；runtime/identityaudit durable closures 已接共享 factory；active handlers={active_handler_count}，unauthorized external effect callsites=0"
        ),
        findings,
    ))
}

fn inbox_sampler_inventory_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for path in [
        TARGET,
        IDENTITYAUDIT_EVENTING_TARGET,
        "assemblies/settingsonly/src/eventing.rs",
    ] {
        let content = std::fs::read_to_string(root.join(path)).with_context(|| {
            format!("event-transport-guard: read {}", root.join(path).display())
        })?;
        findings.extend(inbox_sampler_inventory_content_findings(path, &content));
    }
    Ok(findings)
}

fn inbox_sampler_inventory_content_findings(path: &str, content: &str) -> Vec<Finding<Rule>> {
    let production = strip_cfg_test_modules(content);
    let Ok(file) = syn::parse_file(&production) else {
        return vec![finding(
            Rule::MissingBundleFragment,
            path.to_string(),
            "supported assembly inbox sampler production AST 无法解析".to_string(),
        )];
    };
    let (worker_name, expected) = match path {
        TARGET => ("inbox-backlog-sampler", 1),
        IDENTITYAUDIT_EVENTING_TARGET => ("identityaudit-inbox-backlog-sampler", 0),
        _ => ("settingsonly-inbox-backlog-sampler", 0),
    };
    let mut visitor = InboxInventoryVisitor::new(worker_name);
    visitor.visit_file(&file);
    [
        ("worker", visitor.worker_literals),
        ("sampler loop", visitor.sampler_calls),
        ("probe", visitor.probe_calls),
    ]
    .into_iter()
    .filter(|(_, count)| *count != expected)
    .map(|(carrier, count)| {
        finding(
            Rule::MissingBundleFragment,
            path.to_string(),
            format!(
                "canonical runtime inbox sampler production {carrier} 期望 {expected} 次，实际 {count}；reference assembly 冻结为零"
            ),
        )
    })
    .collect()
}

struct InboxInventoryVisitor<'a> {
    worker_name: &'a str,
    worker_literals: usize,
    sampler_calls: usize,
    probe_calls: usize,
}

impl<'a> InboxInventoryVisitor<'a> {
    const fn new(worker_name: &'a str) -> Self {
        Self {
            worker_name,
            worker_literals: 0,
            sampler_calls: 0,
            probe_calls: 0,
        }
    }
}

impl<'ast> Visit<'ast> for InboxInventoryVisitor<'_> {
    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        if lit.value() == self.worker_name {
            self.worker_literals += 1;
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let last = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            if last.as_deref() == Some("coordinated_inbox_backlog_sampler_loop") {
                self.sampler_calls += 1;
            }
            if last.as_deref() == Some("parse")
                && path.path.segments.iter().any(|segment| segment.ident == "ProbeName")
                && call.args.iter().any(|arg| matches!(arg, syn::Expr::Path(value) if value.path.is_ident("INBOX_SAMPLER_PROBE")))
            {
                self.probe_calls += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn load_dedicated_runtime_sources(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    DEDICATED_RUNTIME_ASSEMBLY_TARGETS
        .iter()
        .map(|target| {
            let path = root.join(target);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
            Ok((PathBuf::from(target), content))
        })
        .collect()
}

fn load_subscribe_supervise_sources(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    SUBSCRIBE_SUPERVISE_TARGETS
        .iter()
        .map(|target| {
            let path = root.join(target);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
            Ok((PathBuf::from(target), content))
        })
        .collect()
}

fn scan_subscribe_supervise_sources(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    let mut spawn_hits: BTreeMap<&'static str, usize> = SUBSCRIBE_SUPERVISE_SPAWN_FNS
        .iter()
        .map(|name| (*name, 0usize))
        .collect();
    for (path, content) in sources {
        let production = strip_cfg_test_modules(content);
        let Ok(file) = syn::parse_file(&production) else {
            findings.push(finding(
                Rule::ConsumerSubscribeSupervise,
                path.display().to_string(),
                "ackable subscribe supervise 生产路径 AST 无法解析".to_string(),
            ));
            continue;
        };
        if file_string_literals_contain_excluding_doc(&file, SUBSCRIBE_SUPERVISE_FORBIDDEN) {
            findings.push(finding(
                Rule::ConsumerSubscribeSupervise,
                path.display().to_string(),
                format!(
                    "禁止 subscribe 失败 one-shot `{SUBSCRIBE_SUPERVISE_FORBIDDEN}`；须退避重试直至 shutdown cancel"
                ),
            ));
        }
        for spawn_name in SUBSCRIBE_SUPERVISE_SPAWN_FNS {
            let Some(item_fn) = find_item_fn_by_name(&file, spawn_name) else {
                continue;
            };
            *spawn_hits.entry(spawn_name).or_insert(0) += 1;
            if !fn_body_calls_ident(item_fn, SUBSCRIBE_SUPERVISE_REQUIRED) {
                findings.push(finding(
                    Rule::ConsumerSubscribeSupervise,
                    path.display().to_string(),
                    format!(
                        "`{spawn_name}` 生产函数体必须调用 `{SUBSCRIBE_SUPERVISE_REQUIRED}`（until-cancel subscribe 监督循环）；函数定义标识符诱饵不算"
                    ),
                ));
            }
        }
    }
    for spawn_name in SUBSCRIBE_SUPERVISE_SPAWN_FNS {
        if spawn_hits.get(spawn_name).copied().unwrap_or(0) == 0 {
            findings.push(finding(
                Rule::ConsumerSubscribeSupervise,
                "SUBSCRIBE_SUPERVISE_TARGETS".to_string(),
                format!(
                    "required spawn `{spawn_name}` 未在任何 SUBSCRIBE_SUPERVISE_TARGETS 中定义（守卫不得因缺席 continue 空转）"
                ),
            ));
        }
    }
    findings
}

/// 扫文件内字符串字面量是否含 `needle`；跳过 `#[doc = "..."]`（禁串不得靠 rustdoc 误红）。
fn file_string_literals_contain_excluding_doc(file: &syn::File, needle: &str) -> bool {
    struct LitVisitor<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for LitVisitor<'_> {
        fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
            if attr.path().is_ident("doc") {
                return;
            }
            syn::visit::visit_attribute(self, attr);
        }

        fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
            if lit.value().contains(self.needle) {
                self.found = true;
            }
        }
    }
    let mut visitor = LitVisitor {
        needle,
        found: false,
    };
    visitor.visit_file(file);
    visitor.found
}

fn find_item_fn_by_name<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item_fn) if item_fn.sig.ident == name => Some(item_fn),
        syn::Item::Mod(module) => module.content.as_ref().and_then(|(_, items)| {
            items.iter().find_map(|nested| match nested {
                syn::Item::Fn(item_fn) if item_fn.sig.ident == name => Some(item_fn),
                _ => None,
            })
        }),
        _ => None,
    })
}

fn fn_body_calls_ident(item_fn: &syn::ItemFn, name: &str) -> bool {
    struct CallVisitor<'a> {
        name: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for CallVisitor<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if call_ident(&node.func).as_deref() == Some(self.name) {
                self.found = true;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut visitor = CallVisitor { name, found: false };
    visitor.visit_block(&item_fn.block);
    visitor.found
}

/// Drop `#[cfg(test)] mod ...` bodies (including nested) so synthetic red / anti-vacuity only see production paths.
fn strip_cfg_test_modules(content: &str) -> String {
    let Ok(file) = syn::parse_file(content) else {
        return content.to_string();
    };
    strip_cfg_test_items(file.items)
        .into_iter()
        .map(|item| item.to_token_stream().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_cfg_test_items(items: Vec<syn::Item>) -> Vec<syn::Item> {
    let mut kept = Vec::new();
    for item in items {
        match item {
            syn::Item::Mod(module) if is_claim_test_only(&module.attrs) => {}
            syn::Item::Mod(mut module) => {
                if let Some((brace, nested)) = module.content.take() {
                    module.content = Some((brace, strip_cfg_test_items(nested)));
                }
                kept.push(syn::Item::Mod(module));
            }
            other => kept.push(other),
        }
    }
    kept
}

#[derive(Default)]
struct DedicatedRuntimeVisitor {
    builders: Vec<String>,
}

impl<'ast> Visit<'ast> for DedicatedRuntimeVisitor {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !is_claim_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !is_claim_test_only(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(call.func.as_ref(), syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "new_current_thread"))
        {
            self.builders.push(normalized_tokens(&call.func));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn scan_dedicated_runtime_sources(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for (path, content) in sources {
        let Ok(file) = syn::parse_file(content) else {
            findings.push(finding(
                Rule::DedicatedRuntimeFunnel,
                path.display().to_string(),
                "dedicated runtime assembly Rust AST 无法解析".to_string(),
            ));
            continue;
        };
        let mut visitor = DedicatedRuntimeVisitor::default();
        visitor.visit_file(&file);
        for builder in visitor.builders {
            findings.push(finding(
                Rule::DedicatedRuntimeFunnel,
                path.display().to_string(),
                format!(
                    "production assembly 禁止手写 current-thread runtime `{builder}`；必须消费 eventexec typed factory"
                ),
            ));
        }
    }
    findings
}

fn runtime_consumer_tx_compat_findings(
    runtime_lib: &str,
    compatibility_file_exists: bool,
) -> Vec<Finding<Rule>> {
    let legacy_module_declared = syn::parse_file(runtime_lib).is_ok_and(|file| {
        file.items
            .iter()
            .any(|item| matches!(item, syn::Item::Mod(module) if module.ident == "consumer_tx"))
    });
    if !legacy_module_declared && !compatibility_file_exists {
        return Vec::new();
    }
    vec![finding(
        Rule::MissingBundleFragment,
        RUNTIME_LIB_TARGET.to_string(),
        "runtime 不得保留 consumer_tx compatibility carrier；调用方必须直接引用 eventing-composition"
            .to_string(),
    )]
}

#[derive(Debug)]
struct ConsumerPolicyCallable {
    path: PathBuf,
    name: String,
    calls: BTreeSet<String>,
    raw_calls: Vec<String>,
    root: bool,
}

#[derive(Default)]
struct ConsumerPolicyCallVisitor {
    calls: BTreeSet<String>,
    raw_calls: Vec<String>,
    aliases: BTreeMap<String, String>,
    raw_bindings: BTreeSet<String>,
    raw_function_aliases: BTreeSet<String>,
}

impl ConsumerPolicyCallVisitor {
    fn new(signature: &syn::Signature, aliases: &BTreeMap<String, String>) -> Self {
        let mut visitor = Self {
            aliases: aliases.clone(),
            ..Self::default()
        };
        for input in &signature.inputs {
            let syn::FnArg::Typed(input) = input else {
                continue;
            };
            if raw_external_effect_owner(&normalized_tokens(&input.ty))
                && let syn::Pat::Ident(binding) = input.pat.as_ref()
            {
                visitor.raw_bindings.insert(binding.ident.to_string());
            }
        }
        visitor
    }

    fn resolve_alias(&self, name: &str) -> String {
        let mut resolved = name.to_string();
        let mut seen = BTreeSet::new();
        while seen.insert(resolved.clone()) {
            let Some(next) = self.aliases.get(&resolved) else {
                break;
            };
            resolved = next.clone();
        }
        resolved
    }

    fn receiver_is_raw(&self, receiver: &syn::Expr, rendered: &str) -> bool {
        if raw_external_effect_owner(rendered)
            || raw_external_effect_chain(rendered)
            || matches!(
                peel_expr(receiver),
                syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| {
                        self.raw_bindings.contains(&segment.ident.to_string())
                    })
            )
        {
            return true;
        }
        false
    }
}

impl<'ast> Visit<'ast> for ConsumerPolicyCallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = peel_expr(&node.func)
            && let Some(segment) = path.path.segments.last()
        {
            let name = segment.ident.to_string();
            let resolved = self.resolve_alias(&name);
            let target = resolved.rsplit("::").next().unwrap_or(&resolved);
            if self.raw_function_aliases.contains(&name)
                || raw_external_effect_method(target, Some(&resolved))
            {
                self.raw_calls.push(normalized_tokens(node));
            }
            self.calls.insert(target.to_string());
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let receiver = normalized_tokens(&node.receiver);
        if raw_external_effect_method(&method, Some(&receiver))
            || (self.receiver_is_raw(&node.receiver, &receiver)
                && raw_external_effect_operation(&method))
        {
            self.raw_calls.push(normalized_tokens(node));
        }
        self.calls.insert(method);
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(binding) = &node.pat
            && let Some(init) = &node.init
            && let syn::Expr::Path(path) = peel_expr(&init.expr)
            && let Some(segment) = path.path.segments.last()
        {
            let alias = binding.ident.to_string();
            let rendered = normalized_tokens(&path.path);
            let resolved = self.resolve_alias(&segment.ident.to_string());
            let target = resolved.rsplit("::").next().unwrap_or(&resolved);
            if self
                .raw_function_aliases
                .contains(&segment.ident.to_string())
                || raw_external_effect_method(target, Some(&rendered))
            {
                self.raw_function_aliases.insert(alias);
            } else {
                self.aliases.insert(alias, resolved);
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        collect_consumer_policy_use_aliases(&node.tree, String::new(), &mut self.aliases);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(segment) = node.path.segments.last() {
            self.calls.insert(segment.ident.to_string());
        }
        syn::visit::visit_macro(self, node);
    }
}

fn raw_external_effect_method(method: &str, receiver: Option<&str>) -> bool {
    if method == "publish" {
        return true;
    }
    let receiver = receiver.unwrap_or_default().to_ascii_lowercase();
    (raw_external_effect_owner(&receiver) || raw_external_effect_chain(&receiver))
        && raw_external_effect_operation(method)
}

fn raw_external_effect_owner(rendered: &str) -> bool {
    let rendered = rendered.to_ascii_lowercase();
    [
        "publisher",
        "outboxemitter",
        "objectstore",
        "object_store",
        "httpclient",
        "email",
        "mailer",
        "mdm",
        "cloud",
        "reqwest",
        "s3",
    ]
    .iter()
    .any(|marker| rendered.contains(marker))
}

fn raw_external_effect_chain(rendered: &str) -> bool {
    let rendered = rendered.to_ascii_lowercase();
    [
        ".post(",
        ".get(",
        ".put(",
        ".patch(",
        ".delete(",
        ".request(",
    ]
    .iter()
    .any(|marker| rendered.contains(marker))
}

fn raw_external_effect_operation(method: &str) -> bool {
    matches!(
        method,
        "send" | "request" | "execute" | "post" | "put" | "put_object" | "upload" | "delete_object"
    )
}

fn raw_external_effect_tokens(tokens: &str) -> bool {
    let tokens = tokens.to_ascii_lowercase();
    tokens.contains(".publish(")
        || tokens.contains("::publish(")
        || ((raw_external_effect_owner(&tokens) || raw_external_effect_chain(&tokens))
            && [
                ".send(",
                ".request(",
                ".execute(",
                ".put(",
                ".put_object(",
                ".upload(",
                ".delete_object(",
            ]
            .iter()
            .any(|operation| tokens.contains(operation)))
}

fn collect_consumer_policy_use_aliases(
    tree: &syn::UseTree,
    prefix: String,
    aliases: &mut BTreeMap<String, String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let prefix = if prefix.is_empty() {
                path.ident.to_string()
            } else {
                format!("{prefix}::{}", path.ident)
            };
            collect_consumer_policy_use_aliases(&path.tree, prefix, aliases);
        }
        syn::UseTree::Name(name) => {
            let target = if prefix.is_empty() {
                name.ident.to_string()
            } else {
                format!("{prefix}::{}", name.ident)
            };
            aliases.insert(name.ident.to_string(), target);
        }
        syn::UseTree::Rename(rename) => {
            let target = if prefix.is_empty() {
                rename.ident.to_string()
            } else {
                format!("{prefix}::{}", rename.ident)
            };
            aliases.insert(rename.rename.to_string(), target);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_consumer_policy_use_aliases(tree, prefix.clone(), aliases);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn consumer_policy_function_is_root(
    owner: Option<&str>,
    name: &str,
    signature: &str,
    body: &str,
) -> bool {
    let owner = owner.unwrap_or_default();
    name.contains("consumer_tx_handler")
        || signature.contains("ConsumerTxHandler<")
        || body.contains("SubscriberCapability::")
        || body.contains("ConsumerTxPlan::")
        || body.contains("spawn_consumer_ackable_tx_subscriber")
        || (owner.contains("ConfigVersionReconciler") && name == "reconcile")
}

fn collect_consumer_policy_callables(
    path: &Path,
    items: &[syn::Item],
    inherited_aliases: &BTreeMap<String, String>,
    callables: &mut Vec<ConsumerPolicyCallable>,
) {
    let mut aliases = inherited_aliases.clone();
    for item in items {
        if let syn::Item::Use(item) = item {
            collect_consumer_policy_use_aliases(&item.tree, String::new(), &mut aliases);
        }
    }
    for item in items {
        if has_test_attr(match item {
            syn::Item::Fn(item) => &item.attrs,
            syn::Item::Impl(item) => &item.attrs,
            syn::Item::Macro(item) => &item.attrs,
            syn::Item::Mod(item) => &item.attrs,
            _ => &[],
        }) {
            continue;
        }
        match item {
            syn::Item::Fn(function) => {
                let body = normalized_tokens(&function.block);
                let signature = normalized_tokens(&function.sig);
                let mut visitor = ConsumerPolicyCallVisitor::new(&function.sig, &aliases);
                visitor.visit_block(&function.block);
                callables.push(ConsumerPolicyCallable {
                    path: path.to_path_buf(),
                    name: function.sig.ident.to_string(),
                    calls: visitor.calls,
                    raw_calls: visitor.raw_calls,
                    root: consumer_policy_function_is_root(
                        None,
                        &function.sig.ident.to_string(),
                        &signature,
                        &body,
                    ),
                });
            }
            syn::Item::Impl(item) => {
                let owner = normalized_tokens(&item.self_ty);
                for method in &item.items {
                    let syn::ImplItem::Fn(method) = method else {
                        continue;
                    };
                    if has_test_attr(&method.attrs) {
                        continue;
                    }
                    let body = normalized_tokens(&method.block);
                    let signature = normalized_tokens(&method.sig);
                    let mut visitor = ConsumerPolicyCallVisitor::new(&method.sig, &aliases);
                    visitor.visit_block(&method.block);
                    callables.push(ConsumerPolicyCallable {
                        path: path.to_path_buf(),
                        name: method.sig.ident.to_string(),
                        calls: visitor.calls,
                        raw_calls: visitor.raw_calls,
                        root: consumer_policy_function_is_root(
                            Some(&owner),
                            &method.sig.ident.to_string(),
                            &signature,
                            &body,
                        ),
                    });
                }
            }
            syn::Item::Macro(item) => {
                if let Some(ident) = &item.ident {
                    let body = normalized_tokens(&item.mac.tokens);
                    let raw_calls = if raw_external_effect_tokens(&body) {
                        vec![body]
                    } else {
                        Vec::new()
                    };
                    callables.push(ConsumerPolicyCallable {
                        path: path.to_path_buf(),
                        name: ident.to_string(),
                        calls: BTreeSet::new(),
                        raw_calls,
                        root: false,
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_consumer_policy_callables(path, nested, &aliases, callables);
                }
            }
            _ => {}
        }
    }
}

fn scan_consumer_policy_sources(sources: &[(PathBuf, String)]) -> (usize, Vec<Finding<Rule>>) {
    let mut callables = Vec::new();
    let mut findings = Vec::new();
    for (path, source) in sources {
        match syn::parse_file(source) {
            Ok(file) => collect_consumer_policy_callables(
                path,
                &file.items,
                &BTreeMap::new(),
                &mut callables,
            ),
            Err(error) => findings.push(finding(
                Rule::ConsumerExternalEffectCapability,
                path.display().to_string(),
                format!("ConsumerTx policy source AST 无法解析: {error}"),
            )),
        }
    }

    let root_count = callables.iter().filter(|callable| callable.root).count();
    let mut reachable = callables
        .iter()
        .enumerate()
        .filter_map(|(index, callable)| callable.root.then_some(index))
        .collect::<BTreeSet<_>>();
    let mut frontier = reachable.iter().copied().collect::<Vec<_>>();
    while let Some(index) = frontier.pop() {
        let calls = callables[index].calls.clone();
        let scope = consumer_policy_source_scope(&callables[index].path);
        for call in calls
            .into_iter()
            .filter(|call| consumer_policy_call_is_traversable(call))
        {
            let candidates = callables
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    candidate.name == call && consumer_policy_source_scope(&candidate.path) == scope
                })
                .map(|(candidate_index, _)| candidate_index)
                .collect::<Vec<_>>();
            if candidates.len() > 4 {
                findings.push(finding(
                    Rule::ConsumerExternalEffectCapability,
                    callables[index].path.display().to_string(),
                    format!(
                        "ConsumerTx policy ambiguous helper resolution for `{call}`: {} same-scope candidates exceed limit 4",
                        candidates.len()
                    ),
                ));
                continue;
            }
            for candidate_index in candidates {
                if reachable.insert(candidate_index) {
                    frontier.push(candidate_index);
                }
            }
        }
    }

    for index in reachable {
        let callable = &callables[index];
        for raw_call in &callable.raw_calls {
            findings.push(finding(
                Rule::ConsumerExternalEffectCapability,
                callable.path.display().to_string(),
                format!(
                    "unauthorized external effect reachable from ConsumerTx policy capability at `{}`: `{raw_call}`",
                    callable.name
                ),
            ));
        }
    }
    (root_count, findings)
}

fn consumer_policy_source_scope(path: &Path) -> PathBuf {
    path.components().take(2).collect()
}

fn consumer_policy_call_is_traversable(name: &str) -> bool {
    !matches!(
        name,
        "and_then"
            | "as_ref"
            | "as_str"
            | "clone"
            | "collect"
            | "config"
            | "contains"
            | "execute"
            | "expect"
            | "from"
            | "from_snapshot"
            | "get"
            | "insert"
            | "into"
            | "key"
            | "map"
            | "map_err"
            | "new"
            | "ok_or"
            | "ok_or_else"
            | "parse"
            | "push"
            | "register"
            | "shutdown"
            | "tenant"
            | "to_owned"
            | "to_string"
            | "try_from"
            | "unwrap_or"
            | "unwrap_or_else"
            | "version"
    )
}

fn scan_consumer_external_effect_capabilities(root: &Path) -> Result<(usize, Vec<Finding<Rule>>)> {
    let sources = producer_source_files(root)?
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("ConsumerTx policy guard: read {}", path.display()))?;
            Ok((rel_path(root, &path), source))
        })
        .collect::<Result<Vec<_>>>()?;
    let (root_count, mut findings) = scan_consumer_policy_sources(&sources);
    if root_count == 0 {
        findings.push(finding(
            Rule::ConsumerExternalEffectCapability,
            TARGET,
            "ConsumerTx policy guard 未发现 registration/plan/handler/executor capability root"
                .to_string(),
        ));
    }

    let active_subscriptions = generated::event::EVENTS
        .iter()
        .flat_map(|event| event.subscriptions().iter())
        .collect::<Vec<_>>();
    let active_handler_count = active_subscriptions.len();
    if active_subscriptions.is_empty() {
        findings.push(finding(
            Rule::ConsumerExternalEffectCapability,
            "generated::event::EVENTS",
            "ConsumerTx active handler projection is empty".to_string(),
        ));
    }
    for subscription in active_subscriptions {
        if !matches!(
            subscription.external_effect_policy(),
            vocab::ExternalEffectPolicy::TransactionalOnly | vocab::ExternalEffectPolicy::Reconcile
        ) {
            findings.push(finding(
                Rule::ConsumerExternalEffectCapability,
                subscription.group(),
                format!(
                    "active ConsumerTx policy lacks production capability/executor: {:?}",
                    subscription.external_effect_policy()
                ),
            ));
        }
    }
    findings.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.detail.cmp(&right.detail))
    });
    Ok((active_handler_count, findings))
}

#[derive(Debug)]
struct ActiveEvent {
    contract_id: String,
    spec_path: String,
}

fn scan_event_producers(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let events = load_active_events(root)?;
    let mut facts = ProducerFacts::default();
    let mut findings = Vec::new();
    for path in producer_source_files(root)? {
        let rel = rel_path(root, &path);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event producer guard: read {}", path.display()))?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("event producer guard: parse {}", path.display()))?;
        let imports = SpecImports::from_file(&file);
        let mut visitor = ProducerVisitor::new(&imports, &rel, &mut facts, &mut findings);
        visitor.visit_file(&file);
    }

    for event in &events {
        findings.extend(validate_event_facts(event, &facts));
    }
    Ok(findings)
}

fn producer_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for top in BYPASS_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            if is_excluded(&member) {
                continue;
            }
            let src = member.join("src");
            if !src.is_dir() {
                continue;
            }
            files.extend(
                rust_files_under(&src)?
                    .into_iter()
                    .filter(|path| !is_producer_test_file(path)),
            );
        }
    }
    for leaf in BYPASS_LEAF_CRATES {
        let src = root.join(leaf).join("src");
        if src.is_dir() {
            files.extend(
                rust_files_under(&src)?
                    .into_iter()
                    .filter(|path| !is_producer_test_file(path)),
            );
        }
    }
    Ok(files.into_iter().collect())
}

fn is_producer_test_file(path: &Path) -> bool {
    if crate::src_scan::is_crate_internal_integration_test_source(path) {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
        || path.components().any(|part| part.as_os_str() == "tests")
}

fn validate_event_facts(event: &ActiveEvent, facts: &ProducerFacts) -> Vec<Finding<Rule>> {
    if facts.emits.contains(&event.spec_path) {
        Vec::new()
    } else {
        vec![finding(
            Rule::ProducerTopology,
            event.contract_id.clone(),
            format!(
                "active event 缺少 generated `{}` per-event emit production witness",
                event.spec_path
            ),
        )]
    }
}

fn load_active_events(root: &Path) -> Result<Vec<ActiveEvent>> {
    let contract_root = root.join(EVENT_CONTRACT_ROOT);
    let mut events = Vec::new();
    let mut stack = vec![contract_root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("event producer guard: read dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some("contract.toml") {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            let doc: toml::Value = toml::from_str(&content)
                .with_context(|| format!("event producer guard: parse {}", path.display()))?;
            if doc.get("kind").and_then(toml::Value::as_str) != Some("event")
                || doc.get("lifecycle").and_then(toml::Value::as_str) != Some("active")
            {
                continue;
            }
            let contract_id = required_toml_str(&doc, "id", &path)?;
            required_toml_str(&doc, "owner", &path)?;
            let version = required_toml_str(&doc, "version", &path)?;
            let relative = path
                .strip_prefix(root.join(EVENT_CONTRACT_ROOT))
                .unwrap_or(&path);
            let segments: Vec<_> = relative.components().collect();
            let slug = if segments.len() == 4 {
                Some(segments[2].as_os_str().to_string_lossy().replace('-', "_"))
            } else {
                None
            };
            let spec_path = event_spec_path(relative, version, slug.as_deref())?;
            events.push(ActiveEvent {
                contract_id: contract_id.to_string(),
                spec_path,
            });
        }
    }
    events.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    Ok(events)
}

fn event_spec_path(relative: &Path, version: &str, slug: Option<&str>) -> Result<String> {
    let segments: Vec<_> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(domain) = segments.first() else {
        anyhow::bail!("event contract path has no domain: {}", relative.display());
    };
    if segments
        .get(1)
        .is_none_or(|path_version| path_version != version)
    {
        anyhow::bail!(
            "event contract path/version mismatch: {} vs {version}",
            relative.display()
        );
    }
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    Ok(match slug {
        Some(slug) => format!("generated::event::{module}::{slug}::SPEC"),
        None => format!("generated::event::{module}::SPEC"),
    })
}

fn required_toml_str<'a>(doc: &'a toml::Value, key: &str, path: &Path) -> Result<&'a str> {
    doc.get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{} missing string `{key}`", path.display()))
}

#[derive(Default)]
struct ProducerFacts {
    emits: BTreeSet<String>,
}

#[derive(Default)]
struct SpecImports {
    module_aliases: BTreeMap<String, String>,
    emit_aliases: BTreeMap<String, String>,
}

impl SpecImports {
    fn from_file(file: &syn::File) -> Self {
        let mut imports = Self::default();
        for item in &file.items {
            if let syn::Item::Use(item_use) = item {
                collect_spec_imports(&item_use.tree, Vec::new(), &mut imports);
            }
        }
        imports
    }

    fn resolve_emit(&self, expr: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = peel_expr(expr) else {
            return None;
        };
        if path.path.segments.len() == 1
            && let Some(canonical) = self
                .emit_aliases
                .get(&path.path.segments[0].ident.to_string())
        {
            return Some(format!("{canonical}::SPEC"));
        }
        if path.path.segments.last()?.ident != "emit" {
            return None;
        }
        let mut module = path.path.clone();
        module.segments.pop();
        let rendered = module.to_token_stream().to_string().replace(' ', "");
        if rendered.starts_with("generated::event::") {
            return Some(format!("{rendered}::SPEC"));
        }
        if module.segments.len() == 1 {
            let ident = module.segments[0].ident.to_string();
            if let Some(canonical) = self.module_aliases.get(&ident) {
                return Some(format!("{canonical}::SPEC"));
            }
        }
        None
    }
}

fn collect_spec_imports(tree: &syn::UseTree, mut prefix: Vec<String>, imports: &mut SpecImports) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_spec_imports(&path.tree, prefix, imports);
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            if prefix.first().is_some_and(|part| part == "generated")
                && prefix.get(1).is_some_and(|part| part == "event")
                && let Some(alias) = prefix.last()
            {
                imports
                    .module_aliases
                    .insert(alias.clone(), prefix.join("::"));
            }
        }
        syn::UseTree::Rename(rename) if rename.ident == "self" => {
            if prefix.first().is_some_and(|part| part == "generated")
                && prefix.get(1).is_some_and(|part| part == "event")
            {
                imports
                    .module_aliases
                    .insert(rename.rename.to_string(), prefix.join("::"));
            }
        }
        syn::UseTree::Name(name) if name.ident == "emit" => {
            if prefix.first().is_some_and(|part| part == "generated")
                && prefix.get(1).is_some_and(|part| part == "event")
            {
                imports
                    .emit_aliases
                    .insert("emit".to_string(), prefix.join("::"));
            }
        }
        syn::UseTree::Rename(rename) if rename.ident == "emit" => {
            if prefix.first().is_some_and(|part| part == "generated")
                && prefix.get(1).is_some_and(|part| part == "event")
            {
                imports
                    .emit_aliases
                    .insert(rename.rename.to_string(), prefix.join("::"));
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_spec_imports(item, prefix.clone(), imports);
            }
        }
        syn::UseTree::Glob(_) | syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
    }
}

struct ProducerVisitor<'a> {
    imports: &'a SpecImports,
    path: &'a Path,
    facts: &'a mut ProducerFacts,
    findings: &'a mut Vec<Finding<Rule>>,
}

impl<'a> ProducerVisitor<'a> {
    fn new(
        imports: &'a SpecImports,
        path: &'a Path,
        facts: &'a mut ProducerFacts,
        findings: &'a mut Vec<Finding<Rule>>,
    ) -> Self {
        Self {
            imports,
            path,
            facts,
            findings,
        }
    }

    fn visit_production_block(&mut self, ident: &syn::Ident, block: &syn::Block) {
        let mut function = FunctionProducerVisitor {
            imports: self.imports,
            emits: BTreeSet::new(),
        };
        function.visit_block(block);
        if function.emits.len() > 1 {
            self.findings.push(finding(
                Rule::ProducerTopology,
                self.path.display().to_string(),
                format!("函数 `{ident}` 必须且只能使用一个 generated per-event emit contract"),
            ));
        } else if let Some(spec) = function.emits.into_iter().next() {
            self.facts.emits.insert(spec);
        }
    }
}

impl<'ast> Visit<'ast> for ProducerVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.ident == "tests" || has_test_attr(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_test_attr(&node.attrs) {
            return;
        }
        self.visit_production_block(&node.sig.ident, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_test_attr(&node.attrs) {
            return;
        }
        self.visit_production_block(&node.sig.ident, &node.block);
    }
}

struct FunctionProducerVisitor<'a> {
    imports: &'a SpecImports,
    emits: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for FunctionProducerVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(spec) = self.imports.resolve_emit(&node.func) {
            self.emits.insert(spec);
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn peel_expr(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        expr = match expr {
            syn::Expr::Paren(paren) => &paren.expr,
            syn::Expr::Group(group) => &group.expr,
            syn::Expr::Reference(reference) => &reference.expr,
            syn::Expr::Try(try_expr) => &try_expr.expr,
            syn::Expr::Await(await_expr) => &await_expr.base,
            _ => return expr,
        };
    }
}

fn call_ends_with(expr: &syn::Expr, owner: &str, method: &str) -> bool {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return false;
    };
    let mut segments = path.path.segments.iter().rev();
    matches!(segments.next(), Some(segment) if segment.ident == method)
        && matches!(segments.next(), Some(segment) if segment.ident == owner)
}

fn call_ident(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr.meta.to_token_stream().to_string().contains("test"))
    })
}

fn scan_runtime_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in RUNTIME_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::RedisConsumerClaimer,
                path.display().to_string(),
                format!(
                    "禁止 runtime event consumer 重新接入旧 claimer/handler 路径: `{forbidden}`"
                ),
            ));
        }
    }
    for forbidden in runtime_redis_inbox_fragments(content) {
        findings.push(finding(
            Rule::RedisConsumerClaimer,
            path.display().to_string(),
            format!("禁止 runtime event consumer 重新接入 Redis claimer: `{forbidden}`"),
        ));
    }
    findings.extend(runtime_shape_findings(path, content));
    findings
}

#[derive(Default)]
struct RuntimeShape {
    delegated_events_bridge: bool,
    bridged_wiring_field: bool,
    bridged_wiring_consumer: bool,
    required_worker_probe_bundle: bool,
    policy_bound_worker_activation: bool,
}

fn runtime_shape_findings(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            "runtime event transport Rust AST 无法解析".to_string(),
        )];
    };
    let mut shape = RuntimeShape::default();
    for item in &file.items {
        match item {
            syn::Item::Struct(item) if item.ident == "EventTransportWiring" => {
                shape.bridged_wiring_field = item.fields.iter().any(|field| {
                    field
                        .ident
                        .as_ref()
                        .is_some_and(|ident| ident == "subscribers")
                        && matches!(field.vis, syn::Visibility::Inherited)
                        && normalized_tokens(&field.ty) == "BridgedSubscriptions"
                });
            }
            syn::Item::Fn(item) if item.sig.ident == "bridge_generated_subscriptions" => {
                let body = normalized_tokens(&item.block);
                shape.delegated_events_bridge = body
                    .contains("eventing_composition::bridge_generated_subscriptions(bindings)")
                    && !body.contains("generated::event::EVENTS");
            }
            syn::Item::Fn(item) if item.sig.ident == "wire_event_transport" => {
                shape.bridged_wiring_consumer = item
                    .sig
                    .inputs
                    .iter()
                    .any(|input| normalized_tokens(input).contains("wiring:EventTransportWiring"))
                    && normalized_tokens(&item.block)
                        .contains("EventTransportWiring{pg,distributed,subscribers,cfg,worker,audit_key,admissions,}=wiring");
            }
            syn::Item::Fn(item) if item.sig.ident == "wire_consumer_resource_bundle" => {
                let body = normalized_tokens(&item.block);
                shape.required_worker_probe_bundle = [
                    "pg.infra().inbox()",
                    "LeaseConfig::from_ttl(inbox.lease_ttl())",
                    "dead_letter(security.dlx_payload_protector.clone())",
                    "consumer_tx_worker_for_subscription(",
                    "matchsubscription.readiness()",
                    "SubscriberReadiness::Required=>",
                    "module.push_worker(worker)",
                    "module.push_probe(consumer_probe)",
                    "wire_inbox_sweeper(pg,timing,write_admission,module)?",
                ]
                .iter()
                .all(|required| body.contains(required));
            }
            syn::Item::Fn(item) if item.sig.ident == "consumer_tx_worker_for_subscription" => {
                let body = normalized_tokens(&item.block);
                shape.policy_bound_worker_activation = [
                    "matchtoken.dispatch()",
                    "AuditConsumerFactory::new(pg,audit_key.context(",
                    ").worker(token,inputs)",
                    "SettingsConsumerFactory::new(pg).worker(token,inputs)",
                ]
                .iter()
                .all(|required| body.contains(required))
                    && match_is_exhaustive_for_dispatch(item, "token.dispatch()");
            }
            _ => {}
        }
    }

    [
        (
            shape.delegated_events_bridge,
            "runtime bridge carrier 必须薄委托 eventing-composition，不得复制 generated registry 解析",
        ),
        (
            shape.bridged_wiring_field && shape.bridged_wiring_consumer,
            "wire_event_transport 必须消费 opaque BridgedSubscriptions bundle",
        ),
        (
            shape.required_worker_probe_bundle && shape.policy_bound_worker_activation,
            "runtime consumer bundle 必须以 Required 穷尽分支成对注册共享 factory worker 与 readyz probe",
        ),
    ]
    .into_iter()
    .filter(|(present, _)| !present)
    .map(|(_, message)| {
        finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            message.to_string(),
        )
    })
    .collect()
}

#[derive(Default)]
struct CompositionShape {
    bridged_private_shape: bool,
    generated_events_bridge: bool,
    feature_admission_closed: bool,
    audit_events_bridge: bool,
    audit_admission_closed: bool,
    resolver_passes_generated_policy: bool,
    handler_mapping: bool,
    adapter_native_external_effect_policy: bool,
    settings_refresh_external_effect_policy: bool,
    policy_bound_worker_activation: bool,
    audit_factory_mapping: bool,
    settings_factory_mapping: bool,
}

#[allow(clippy::cognitive_complexity)] // develop IdentityAudit composition scanner; split tracked separately
fn scan_composition_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            "eventing composition Rust AST 无法解析".to_string(),
        )];
    };
    let mut shape = CompositionShape::default();
    for item in &file.items {
        match item {
            syn::Item::Struct(item) if item.ident == "BridgedSubscription" => {
                let fields = item
                    .fields
                    .iter()
                    .filter_map(|field| {
                        field.ident.as_ref().map(|ident| (ident.to_string(), field))
                    })
                    .collect::<BTreeMap<_, _>>();
                shape.bridged_private_shape = ["event", "subscription", "group", "consumer_tx"]
                    .iter()
                    .all(|name| {
                        fields
                            .get(*name)
                            .is_some_and(|field| matches!(field.vis, syn::Visibility::Inherited))
                    })
                    && !fields.contains_key("handler");
            }
            syn::Item::Fn(item) if item.sig.ident == "bridge_generated_subscriptions" => {
                shape.generated_events_bridge =
                    generated_events_bridge_calls_selector(item, "admitted_dispatch");
            }
            syn::Item::Fn(item) if item.sig.ident == "bridge_generated_audit_subscriptions" => {
                shape.audit_events_bridge =
                    generated_events_bridge_calls_selector(item, "admitted_audit_dispatch");
            }
            syn::Item::Fn(item) if item.sig.ident == "admitted_dispatch" => {
                shape.feature_admission_closed = dispatch_match_is_closed(
                    &item.block,
                    "dispatch",
                    &[
                        "SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit",
                        "SubscriptionDispatchKey::IdentityRoleAssignedV1Audit",
                        "SubscriptionDispatchKey::IdentityRoleRevokedV1Audit",
                        "SubscriptionDispatchKey::IdentitySecurityEventV1Audit",
                        "SubscriptionDispatchKey::IdentitySessionCreatedV1Audit",
                        "SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings",
                    ],
                ) && normalized_tokens(&item.block)
                    .contains("cfg!(feature=\"audit-consumers\")")
                    && normalized_tokens(&item.block)
                        .contains("cfg!(feature=\"settings-consumers\")");
            }
            syn::Item::Fn(item) if item.sig.ident == "admitted_audit_dispatch" => {
                let body = normalized_tokens(&item.block);
                shape.audit_admission_closed = dispatch_match_is_closed(
                    &item.block,
                    "dispatch",
                    &[
                        "SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit",
                        "SubscriptionDispatchKey::IdentityRoleAssignedV1Audit",
                        "SubscriptionDispatchKey::IdentityRoleRevokedV1Audit",
                        "SubscriptionDispatchKey::IdentitySecurityEventV1Audit",
                        "SubscriptionDispatchKey::IdentitySessionCreatedV1Audit",
                        "SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings",
                    ],
                ) && body.contains(
                    "SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings=>false",
                );
            }
            syn::Item::Fn(item) if item.sig.ident == "resolve_parts" => {
                shape.resolver_passes_generated_policy = normalized_tokens(&item.sig)
                    .contains("policy:ExternalEffectPolicy")
                    && normalized_tokens(&item.sig).contains("capability:SubscriberCapability");
                shape.handler_mapping = consumer_tx_plan_resolver_is_closed(item);
            }
            syn::Item::Fn(item) if item.sig.ident == "require_adapter_native" => {
                shape.adapter_native_external_effect_policy =
                    consumer_tx_plan_matcher_is_closed(item, false);
            }
            syn::Item::Fn(item) if item.sig.ident == "require_settings_reconcile" => {
                shape.settings_refresh_external_effect_policy =
                    consumer_tx_plan_matcher_is_closed(item, true);
            }
            syn::Item::Fn(item) if item.sig.ident == "worker_spec" => {
                let signature = normalized_tokens(&item.sig);
                let body = normalized_tokens(&item.block);
                shape.policy_bound_worker_activation = signature.contains("ConsumerTxHandler<P>")
                    && body.contains("spawn_consumer_ackable_tx_subscriber(");
            }
            syn::Item::Impl(item) => {
                let owner = normalized_tokens(&item.self_ty);
                for method in &item.items {
                    let syn::ImplItem::Fn(method) = method else {
                        continue;
                    };
                    if method.sig.ident != "worker" {
                        continue;
                    }
                    let body = normalized_tokens(&method.block);
                    if owner.contains("AuditConsumerFactory") {
                        shape.audit_factory_mapping = audit_factory_mapping_is_closed(method);
                    }
                    if owner.contains("SettingsConsumerFactory") {
                        shape.settings_factory_mapping = [
                            "DispatchPlan::ConfigVersionChanged(effect)",
                            ".config_version_changed_consumer_tx(effect)",
                            "worker_spec::<policy::Reconcile,_>(inputs,handler)",
                        ]
                        .iter()
                        .all(|required| body.contains(required));
                    }
                }
            }
            _ => {}
        }
    }

    [
        (
            shape.bridged_private_shape,
            "共享 BridgedSubscription 必须以私有 event/subscription/group/consumer_tx 字段封装，且不得暴露 handler",
        ),
        (
            shape.generated_events_bridge
                && shape.feature_admission_closed
                && shape.audit_events_bridge
                && shape.audit_admission_closed,
            "共享 bridge 必须从 generated::event::EVENTS 单源，穷尽 audit/settings feature admission，并提供不受 feature union 扩张的精确 audit bridge",
        ),
        (
            shape.handler_mapping && shape.resolver_passes_generated_policy,
            "共享 ConsumerTx resolver 必须穷尽 generated dispatch 并携带 externalEffectPolicy/capability",
        ),
        (
            shape.adapter_native_external_effect_policy,
            "共享 ConsumerTx plan 必须闭合匹配 adapter-native + transactional-only capability",
        ),
        (
            shape.settings_refresh_external_effect_policy,
            "共享 ConsumerTx plan 必须闭合匹配 settings refresh + reconcile capability",
        ),
        (
            shape.policy_bound_worker_activation
                && shape.audit_factory_mapping
                && shape.settings_factory_mapping,
            "共享 factory 必须闭合选择五个 Postgres handler 并进入唯一 sealed worker driver",
        ),
    ]
    .into_iter()
    .filter(|(present, _)| !present)
    .map(|(_, detail)| {
        finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            detail.to_string(),
        )
    })
    .collect()
}

fn generated_events_bridge_calls_selector(item: &syn::ItemFn, selector: &str) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(call), _)) = item.block.stmts.last() else {
        return false;
    };
    normalized_tokens(&call.func) == "bridge_subscriptions_with_events_selected"
        && call.args.len() == 3
        && normalized_tokens(&call.args[0]) == "bindings"
        && normalized_tokens(&call.args[1]) == "generated::event::EVENTS"
        && normalized_tokens(&call.args[2]) == selector
}

fn audit_factory_mapping_is_closed(method: &syn::ImplItemFn) -> bool {
    const EXPECTED: [(&str, &str); 5] = [
        (
            "DispatchPlan::SessionCreated",
            "session_created_consumer_tx",
        ),
        ("DispatchPlan::RoleAssigned", "role_assigned_consumer_tx"),
        ("DispatchPlan::RoleRevoked", "role_revoked_consumer_tx"),
        ("DispatchPlan::PolicyUpdated", "policy_updated_consumer_tx"),
        ("DispatchPlan::SecurityEvent", "security_event_consumer_tx"),
    ];

    struct MatchVisitor {
        mappings: BTreeMap<String, Vec<String>>,
        match_count: usize,
        malformed: bool,
    }

    struct HandlerCallVisitor {
        calls: Vec<String>,
        transactional_worker_calls: usize,
    }

    impl<'ast> Visit<'ast> for HandlerCallVisitor {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if normalized_tokens(&node.func) == "worker_spec::<policy::TransactionalOnly,_>"
                && node.args.len() == 2
                && normalized_tokens(&node.args[0]) == "inputs"
                && normalized_tokens(&node.args[1]) == "handler"
            {
                self.transactional_worker_calls += 1;
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let method = node.method.to_string();
            if EXPECTED.iter().any(|(_, expected)| method == *expected) {
                self.calls.push(method);
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    impl<'ast> Visit<'ast> for MatchVisitor {
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if normalized_tokens(&node.expr) != "token.plan" {
                syn::visit::visit_expr_match(self, node);
                return;
            }
            self.match_count += 1;
            for arm in &node.arms {
                let pattern = normalized_tokens(&arm.pat);
                let mut calls = HandlerCallVisitor {
                    calls: Vec::new(),
                    transactional_worker_calls: 0,
                };
                calls.visit_expr(&arm.body);
                let Some((_, expected_handler)) =
                    EXPECTED.iter().find(|(expected, _)| pattern == *expected)
                else {
                    if !calls.calls.is_empty() {
                        self.malformed = true;
                    }
                    continue;
                };
                if arm.guard.is_some()
                    || !matches!(arm.pat, syn::Pat::Path(_))
                    || calls.transactional_worker_calls != 1
                    || calls.calls.as_slice() != [*expected_handler]
                {
                    self.malformed = true;
                }
                if self.mappings.insert(pattern, calls.calls).is_some() {
                    self.malformed = true;
                }
            }
        }
    }

    let mut visitor = MatchVisitor {
        mappings: BTreeMap::new(),
        match_count: 0,
        malformed: false,
    };
    visitor.visit_block(&method.block);
    visitor.match_count == 1
        && !visitor.malformed
        && EXPECTED.iter().all(|(dispatch, handler)| {
            visitor
                .mappings
                .get(*dispatch)
                .is_some_and(|calls| calls.as_slice() == [*handler])
        })
}

fn match_is_exhaustive_for_dispatch(item: &syn::ItemFn, input: &str) -> bool {
    dispatch_match_is_closed(
        &item.block,
        input,
        &[
            "SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit",
            "SubscriptionDispatchKey::IdentityRoleAssignedV1Audit",
            "SubscriptionDispatchKey::IdentityRoleRevokedV1Audit",
            "SubscriptionDispatchKey::IdentitySecurityEventV1Audit",
            "SubscriptionDispatchKey::IdentitySessionCreatedV1Audit",
            "SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings",
        ],
    )
}

fn dispatch_match_is_closed(block: &syn::Block, input: &str, variants: &[&str]) -> bool {
    struct Visitor<'a> {
        input: &'a str,
        variants: &'a [&'a str],
        closed: bool,
    }

    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if normalized_tokens(&node.expr) == self.input {
                let patterns = node
                    .arms
                    .iter()
                    .map(|arm| normalized_tokens(&arm.pat))
                    .collect::<String>();
                self.closed = node
                    .arms
                    .iter()
                    .all(|arm| arm.guard.is_none() && !matches!(arm.pat, syn::Pat::Wild(_)))
                    && self
                        .variants
                        .iter()
                        .all(|variant| patterns.contains(variant));
            }
            syn::visit::visit_expr_match(self, node);
        }
    }

    let mut visitor = Visitor {
        input,
        variants,
        closed: false,
    };
    visitor.visit_block(block);
    visitor.closed
}

fn identityaudit_closure_findings(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            "identityaudit eventing Rust AST 无法解析".to_string(),
        )];
    };
    let mut bridge_and_budget = false;
    let mut consumer_bundle = false;
    let mut audit_dispatch_closure = false;
    for item in &file.items {
        let syn::Item::Fn(item) = item else {
            continue;
        };
        let body = normalized_tokens(&item.block);
        if item.sig.ident == "wire" {
            let bridge =
                body.find("eventing_composition::bridge_generated_audit_subscriptions(bindings)");
            let validate = body.find("validate_audit_closure(subscriptions.subscriptions())");
            let budget_gate = body.find("pg.validate_relay_budget(budget)");
            let connect = body.find("amqp::AmqpRuntimeDeps::connect_with_private_ca(");
            bridge_and_budget = matches!(
                (bridge, validate, budget_gate, connect),
                (Some(bridge), Some(validate), Some(budget_gate), Some(connect))
                    if bridge < validate && validate < budget_gate && budget_gate < connect
            );
        }
        if item.sig.ident == "wire_subscribers" {
            consumer_bundle = [
                "subscriptions:Vec<eventing_composition::BridgedSubscription>",
                "pg.infra().inbox()",
                "LeaseConfig::from_ttl(inbox.lease_ttl())",
                "eventing_composition::AuditConsumerFactory::new(pg,audit_key).worker(",
                "subscription.dispatch_token().clone()",
                "eventing_composition::WorkerInputs::new(",
                "matchsubscription.readiness()",
                "SubscriberReadiness::Required=>",
                "output.push_worker(worker)",
                "output.push_probe(",
                "wire_inbox_sweeper(pg,write_admission,&mutoutput)?",
            ]
            .iter()
            .all(|required| {
                normalized_tokens(&item.sig).contains(required) || body.contains(required)
            });
        }
        if item.sig.ident == "validate_audit_closure" {
            audit_dispatch_closure = body.contains("subscriptions.len()==5")
                && [
                    "SubscriptionDispatchKey::IdentitySessionCreatedV1Audit",
                    "SubscriptionDispatchKey::IdentityRoleAssignedV1Audit",
                    "SubscriptionDispatchKey::IdentityRoleRevokedV1Audit",
                    "SubscriptionDispatchKey::IdentitySecurityEventV1Audit",
                    "SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit",
                ]
                .iter()
                .all(|dispatch| body.contains(dispatch))
                && !body
                    .contains("SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings");
        }
    }

    [
        (
            bridge_and_budget,
            "identityaudit 必须先桥接并验证五条 audit closure，再校验 DB relay budget，最后连接 AMQP",
        ),
        (
            consumer_bundle,
            "identityaudit durable consumer 必须经共享 AuditConsumerFactory/WorkerInputs 并成对注册 Required worker/probe",
        ),
        (
            audit_dispatch_closure,
            "identityaudit 必须精确封闭五条 Identity-to-Audit generated dispatch",
        ),
    ]
    .into_iter()
    .filter(|(present, _)| !present)
    .map(|(_, detail)| {
        finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            detail.to_string(),
        )
    })
    .collect()
}

fn consumer_tx_plan_resolver_is_closed(item: &syn::ItemFn) -> bool {
    let signature = normalized_tokens(&item.sig);
    let body = normalized_tokens(&item.block);
    let mut visitor = ConsumerPolicyMatchVisitor::default();
    visitor.visit_block(&item.block);
    signature.contains("dispatch:SubscriptionDispatchKey")
        && signature.contains("policy:ExternalEffectPolicy")
        && signature.contains("capability:SubscriberCapability")
        && visitor.dispatch_is_closed
        && visitor.policy_is_closed
        && body.contains("require_adapter_native(")
        && body.contains("require_settings_reconcile(")
}

#[derive(Default)]
struct ConsumerPolicyMatchVisitor {
    dispatch_is_closed: bool,
    policy_is_closed: bool,
    has_wildcard: bool,
}

impl<'ast> Visit<'ast> for ConsumerPolicyMatchVisitor {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let input = normalized_tokens(&node.expr);
        if input == "dispatch" {
            self.dispatch_is_closed = !node.arms.is_empty()
                && node.arms.iter().all(|arm| {
                    arm.guard.is_none()
                        && matches!(&arm.pat, syn::Pat::Path(path)
                            if path.path.segments.len() == 2
                                && path.path.segments[0].ident == "SubscriptionDispatchKey")
                });
        }
        if input == "policy" {
            let patterns = node
                .arms
                .iter()
                .map(|arm| normalized_tokens(&arm.pat))
                .collect::<String>();
            self.policy_is_closed = [
                "ExternalEffectPolicy::TransactionalOnly",
                "ExternalEffectPolicy::IdempotencyKey",
                "ExternalEffectPolicy::Reconcile",
                "ExternalEffectPolicy::Compensated",
            ]
            .iter()
            .all(|variant| patterns.contains(variant))
                && node.arms.iter().all(|arm| arm.guard.is_none());
        }
        if node
            .arms
            .iter()
            .any(|arm| matches!(arm.pat, syn::Pat::Wild(_)))
        {
            self.has_wildcard = true;
        }
        syn::visit::visit_expr_match(self, node);
    }
}

fn consumer_tx_plan_matcher_is_closed(item: &syn::ItemFn, reconcile: bool) -> bool {
    let signature = normalized_tokens(&item.sig);
    let body = normalized_tokens(&item.block);
    let mut visitor = ConsumerPolicyMatchVisitor::default();
    visitor.visit_block(&item.block);
    let common = [
        "execution:SubscriptionExecution",
        "effect:Option<SubscriptionEffect>",
        "policy:ExternalEffectPolicy",
        "capability:SubscriberCapability",
    ]
    .iter()
    .all(|required| signature.contains(required));
    let policy_specific = if reconcile {
        body.contains("SubscriptionExecution::DomainEffect")
            && body.contains("Some(SubscriptionEffect::SettingsConfigVersionRefresh)")
            && body.contains("ExternalEffectPolicy::Reconcile")
            && body.contains("SubscriberCapability::DomainReconcile(effect)ifgenerated_matches")
            && body.contains("into_owner::<settings::ConfigVersionReconciler>()")
    } else {
        body.contains("SubscriptionExecution::AdapterNative")
            && body.contains("None")
            && body.contains("ExternalEffectPolicy::TransactionalOnly")
            && body.contains("SubscriberCapability::AdapterNativeTransactionalifgenerated_matches")
            && body.contains("=>Ok(())")
    };
    common && policy_specific && !visitor.has_wildcard
}

fn normalized_tokens(tokens: &impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn runtime_redis_inbox_fragments(content: &str) -> BTreeSet<&'static str> {
    syn::parse_file(content)
        .map(|file| file_runtime_redis_inbox_fragments(&file))
        .unwrap_or_else(|_| text_runtime_redis_inbox_fragments(content))
}

fn text_runtime_redis_inbox_fragments(content: &str) -> BTreeSet<&'static str> {
    let mut fragments = BTreeSet::new();
    if content.contains(RUNTIME_REDIS_INBOX_FRAGMENT) {
        fragments.insert(RUNTIME_REDIS_INBOX_FRAGMENT);
    }
    fragments
}

fn scan_domain_crates(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for crate_root in domain_crate_roots() {
        let abs_root = root.join(crate_root);
        if !abs_root.exists() {
            continue;
        }
        for path in rust_files_under(&abs_root)? {
            let content = std::fs::read_to_string(&path).with_context(|| {
                format!("event-transport-guard: read domain file {}", path.display())
            })?;
            findings.extend(scan_domain_content(&rel_path(root, &path), &content));
        }
    }
    Ok(findings)
}

fn domain_crate_roots() -> Vec<String> {
    crate::layers::DOMAIN_CRATES
        .iter()
        .map(|crate_name| format!("crates/{crate_name}"))
        .collect()
}

fn scan_production_bypasses(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for top in BYPASS_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            if is_excluded(&member) {
                continue;
            }
            scan_bypass_dir(root, &member.join("src"), &mut findings)?;
        }
    }
    for leaf in BYPASS_LEAF_CRATES {
        let dir = root.join(leaf);
        if !is_excluded(&dir) {
            scan_bypass_dir(root, &dir.join("src"), &mut findings)?;
        }
    }
    Ok(findings)
}

fn scan_bypass_dir(root: &Path, dir: &Path, findings: &mut Vec<Finding<Rule>>) -> Result<()> {
    for path in rs_files(dir)? {
        let rel = rel_path(root, &path);
        if is_bypass_allowed(root, &rel)? {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
        findings.extend(scan_bypass_content(&rel, &content));
    }
    Ok(())
}

fn rust_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    files_with_extension_under(dir, "rs")
}

fn files_with_extension_under(dir: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)
            .with_context(|| format!("event-transport-guard: read dir {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn is_bypass_allowed(root: &Path, rel: &Path) -> Result<bool> {
    if BYPASS_ALLOWED_PATHS
        .iter()
        .any(|allowed| rel == Path::new(allowed))
    {
        return Ok(true);
    }
    if rel != Path::new(POSTGRES_FAULT_MATRIX_HARNESS) {
        return Ok(false);
    }
    let lib_path = root.join(POSTGRES_LIB_PATH);
    let lib_content = std::fs::read_to_string(&lib_path)
        .with_context(|| format!("event-transport-guard: read {}", lib_path.display()))?;
    Ok(is_feature_gated_fault_matrix_harness(rel, &lib_content))
}

fn is_feature_gated_fault_matrix_harness(rel: &Path, lib_content: &str) -> bool {
    rel == Path::new(POSTGRES_FAULT_MATRIX_HARNESS)
        && fault_matrix_module_has_feature_gate(lib_content)
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

fn scan_domain_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in DOMAIN_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::DomainConsumerBundleBypass,
                path.display().to_string(),
                format!("consumer inbox/DLX/worker 只能经 runtime bundle 接线，域 crate 禁止片段: `{forbidden}`"),
            ));
        }
    }
    findings
}

fn scan_bypass_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let forbidden = syn::parse_file(content)
        .map(|file| file_bypass_fragments(&file))
        .unwrap_or_else(|_| text_bypass_fragments(content));
    forbidden
        .into_iter()
        .filter(|fragment| !allowed_bypass_exception(path, content, fragment))
        .map(|fragment| {
            finding(
                Rule::ProductionConsumerBundleBypass,
                path.display().to_string(),
                format!(
                    "consumer inbox/worker 只能经 generated topology bridge + runtime bundle 接线，生产 src 禁止片段: `{fragment}`"
                ),
            )
        })
        .collect()
}

fn allowed_bypass_exception(path: &Path, content: &str, fragment: &str) -> bool {
    (path == Path::new("adapters/postgres/src/fault_matrix.rs")
        && fragment == "pg.infra().inbox("
        && content.contains("CONSISTENCY-FAULT-MATRIX-SEAM-01")
        && content.matches("self.deps.infra().inbox()").count() == 3)
        || (path == Path::new(IDENTITYAUDIT_EVENTING_TARGET)
            && fragment == "pg.infra().inbox("
            && identityaudit_closure_findings(path, content).is_empty())
}

fn text_bypass_fragments(content: &str) -> BTreeSet<&'static str> {
    BYPASS_FORBIDDEN
        .iter()
        .copied()
        .filter(|forbidden| content.contains(forbidden))
        .collect()
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

#[derive(Default)]
struct RuntimeVisitor {
    forbidden_infra_aliases: BTreeSet<String>,
    fragments: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for RuntimeVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(pat_ident) = &node.pat
            && let Some(init) = &node.init
            && let Some(InfraReceiver::Forbidden) = classify_runtime_infra_call(&init.expr)
        {
            self.forbidden_infra_aliases
                .insert(pat_ident.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "inbox"
            && expr_is_runtime_forbidden_inbox_receiver(
                &node.receiver,
                &self.forbidden_infra_aliases,
            )
        {
            self.fragments.insert(RUNTIME_REDIS_INBOX_FRAGMENT);
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn file_runtime_redis_inbox_fragments(file: &syn::File) -> BTreeSet<&'static str> {
    let mut visitor = RuntimeVisitor::default();
    visitor.visit_file(file);
    visitor.fragments
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfraReceiver {
    Pg,
    Forbidden,
}

fn expr_is_runtime_forbidden_inbox_receiver(
    expr: &syn::Expr,
    forbidden_aliases: &BTreeSet<String>,
) -> bool {
    if let Some(receiver) = classify_runtime_infra_call(expr) {
        return receiver == InfraReceiver::Forbidden;
    }
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.path.segments.len() == 1
                && forbidden_aliases.contains(&path.path.segments[0].ident.to_string())
    )
}

fn classify_runtime_infra_call(expr: &syn::Expr) -> Option<InfraReceiver> {
    match expr {
        syn::Expr::MethodCall(call) if call.method == "infra" => {
            if expr_mentions_ident(&call.receiver, "pg") {
                Some(InfraReceiver::Pg)
            } else {
                Some(InfraReceiver::Forbidden)
            }
        }
        syn::Expr::Paren(paren) => classify_runtime_infra_call(&paren.expr),
        syn::Expr::Group(group) => classify_runtime_infra_call(&group.expr),
        syn::Expr::Reference(reference) => classify_runtime_infra_call(&reference.expr),
        _ => None,
    }
}

fn expr_mentions_ident(expr: &syn::Expr, ident: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .iter()
            .any(|segment| segment.ident == ident),
        syn::Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(member) if member == ident)
                || expr_mentions_ident(&field.base, ident)
        }
        syn::Expr::MethodCall(call) => expr_mentions_ident(&call.receiver, ident),
        syn::Expr::Paren(paren) => expr_mentions_ident(&paren.expr, ident),
        syn::Expr::Group(group) => expr_mentions_ident(&group.expr, ident),
        syn::Expr::Reference(reference) => expr_mentions_ident(&reference.expr, ident),
        _ => false,
    }
}

#[derive(Default)]
struct BypassVisitor {
    imported_calls: BTreeMap<String, &'static str>,
    infra_aliases: BTreeSet<String>,
    fragments: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for BypassVisitor {
    fn visit_use_tree(&mut self, node: &'ast syn::UseTree) {
        collect_bypass_imports(node, false, &mut self.imported_calls);
        syn::visit::visit_use_tree(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(pat_ident) = &node.pat
            && let Some(init) = &node.init
            && expr_is_infra_call(&init.expr)
        {
            self.infra_aliases.insert(pat_ident.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref()
            && let Some(fragment) = call_path_bypass_fragment(&path.path, &self.imported_calls)
        {
            self.fragments.insert(fragment);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "inbox" && expr_is_infra_receiver(&node.receiver, &self.infra_aliases) {
            self.fragments.insert("pg.infra().inbox(");
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn file_bypass_fragments(file: &syn::File) -> BTreeSet<&'static str> {
    let mut visitor = BypassVisitor::default();
    visitor.visit_file(file);
    visitor.fragments
}

fn collect_bypass_imports(
    tree: &syn::UseTree,
    seen_eventexec: bool,
    imports: &mut BTreeMap<String, &'static str>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            collect_bypass_imports(
                &path.tree,
                seen_eventexec || path.ident == "eventexec",
                imports,
            );
        }
        syn::UseTree::Name(name) if seen_eventexec => {
            if let Some(fragment) = forbidden_spawn_fragment(&name.ident.to_string()) {
                imports.insert(name.ident.to_string(), fragment);
            }
        }
        syn::UseTree::Rename(rename) if seen_eventexec => {
            if let Some(fragment) = forbidden_spawn_fragment(&rename.ident.to_string()) {
                imports.insert(rename.rename.to_string(), fragment);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_bypass_imports(item, seen_eventexec, imports);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
    }
}

fn call_path_bypass_fragment(
    path: &syn::Path,
    imports: &BTreeMap<String, &'static str>,
) -> Option<&'static str> {
    let ident = path.segments.last()?.ident.to_string();
    forbidden_spawn_fragment(&ident).or_else(|| imports.get(&ident).copied())
}

fn forbidden_spawn_fragment(ident: &str) -> Option<&'static str> {
    match ident {
        "spawn_consumer" => Some("spawn_consumer("),
        "spawn_consumer_ackable" => Some("spawn_consumer_ackable("),
        "spawn_consumer_ackable_subscriber" => Some("spawn_consumer_ackable_subscriber("),
        "spawn_consumer_ackable_tx_subscriber" => Some("spawn_consumer_ackable_tx_subscriber("),
        _ => None,
    }
}

fn expr_is_infra_receiver(expr: &syn::Expr, infra_aliases: &BTreeSet<String>) -> bool {
    if expr_is_infra_call(expr) {
        return true;
    }
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.path.segments.len() == 1
                && infra_aliases.contains(&path.path.segments[0].ident.to_string())
    )
}

fn expr_is_infra_call(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::MethodCall(call) if call.method == "infra")
}

const EVENTEXEC_RELAY_PATH: &str = "crates/eventexec/src/relay.rs";
const POSTGRES_OUTBOX_PATH: &str = "adapters/postgres/src/outbox.rs";
const POSTGRES_OUTBOX_SETTLEMENT_PATH: &str = "adapters/postgres/src/cotx/eventing.rs";
const POSTGRES_OUTBOX_ROUTINE_CATALOG_PATH: &str = "adapters/postgres/src/outbox_routine.rs";
const POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH: &str =
    "adapters/postgres/src/integration_tests/outbox_tests.rs";
const OUTBOX_SETTLEMENT_RAW_FUNCTIONS: &[&str] = &[
    "rss_outbox_settle_published",
    "rss_outbox_settle_retry",
    "rss_outbox_mark_dlx",
];
const RELAY_BUDGET_SOURCE_PATHS: &[&str] = &[
    "crates/eventexec/src/relay_config.rs",
    "assemblies/runtime/src/event_transport.rs",
    "assemblies/runtime/src/phase/infra.rs",
    "adapters/amqp/src/conn.rs",
    "adapters/amqp/src/publisher.rs",
    "adapters/amqp/src/bundle.rs",
    "adapters/postgres/src/outbox.rs",
    "adapters/postgres/src/outbox/settlement.rs",
    POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH,
    "adapters/postgres/src/bundle.rs",
    "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
];
const LEGACY_OUTBOX_MIGRATIONS: &[&str] = &[
    "adapters/postgres/migrations/0031_harden_outbox_tenant_scope.sql",
    "adapters/postgres/migrations/0036_add_outbox_schema_columns.sql",
    "adapters/postgres/migrations/0037_outbox_metric_scope_functions.sql",
];
const RETIRED_OUTBOX_FUNCTIONS: &[&str] = &["RSS_OUTBOX_POLL_PENDING", "RSS_OUTBOX_ACQUIRE_LEASE"];
const ATOMIC_OUTBOX_CLAIM_MIGRATION: &str =
    "adapters/postgres/migrations/0057_atomic_outbox_claim.sql";

fn load_relay_budget_sources(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    RELAY_BUDGET_SOURCE_PATHS
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("relay budget guard: read {}", path.display()))?;
            Ok((PathBuf::from(relative), content))
        })
        .collect()
}

#[derive(Debug, Default)]
struct SettlementFunnelScan {
    findings: Vec<Finding<Rule>>,
    canonical_calls: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct ResolvedSettlementSql {
    value: String,
    line: usize,
}

fn scan_settlement_funnel_sources(sources: &[(PathBuf, String)]) -> SettlementFunnelScan {
    let test_only_files = external_cfg_test_module_paths(sources);
    let callable_functions = outbox_callable_catalog(sources);
    let mut scan = SettlementFunnelScan::default();
    for (path, content) in sources.iter().filter(|(path, _)| {
        path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && !test_only_files.contains(path)
    }) {
        let Ok(file) = syn::parse_file(content) else {
            scan.findings.push(finding(
                Rule::PostgresOutboxSettlementFunnel,
                path.display().to_string(),
                "PG-OUTBOX-SETTLEMENT-FUNNEL-01 production Rust AST 无法解析".to_string(),
            ));
            continue;
        };
        if is_claim_test_only(&file.attrs) {
            continue;
        }
        let allowed = path == Path::new(POSTGRES_OUTBOX_SETTLEMENT_PATH);
        let mut visitor = SettlementSqlVisitor {
            path,
            allowed,
            scan: &mut scan,
            bindings: vec![static_string_bindings(&file)],
            builders: vec![BTreeMap::new()],
            local_executor_arguments: if allowed {
                local_settlement_executor_arguments(&file)
            } else {
                BTreeMap::new()
            },
            callable_functions: &callable_functions,
        };
        visitor.visit_file(&file);
    }
    for function in OUTBOX_SETTLEMENT_RAW_FUNCTIONS {
        if !scan.canonical_calls.contains(*function) {
            scan.findings.push(finding(
                Rule::PostgresOutboxSettlementFunnel,
                POSTGRES_OUTBOX_SETTLEMENT_PATH,
                format!(
                    "PG-OUTBOX-SETTLEMENT-FUNNEL-01 缺 canonical raw function `{function}` execution witness"
                ),
            ));
        }
    }
    scan
}

struct SettlementSqlVisitor<'a> {
    path: &'a Path,
    allowed: bool,
    scan: &'a mut SettlementFunnelScan,
    bindings: Vec<BTreeMap<String, ResolvedSettlementSql>>,
    builders: Vec<BTreeMap<String, ResolvedSettlementSql>>,
    local_executor_arguments: BTreeMap<String, BTreeSet<usize>>,
    callable_functions: &'a BTreeMap<String, String>,
}

impl SettlementSqlVisitor<'_> {
    fn inspect_sql(&mut self, sql: &str, line: usize) {
        for function in raw_settlement_function_calls(sql) {
            let canonical = OUTBOX_SETTLEMENT_RAW_FUNCTIONS.contains(&function.as_str());
            if self.allowed && canonical {
                self.scan.canonical_calls.insert(function);
            } else {
                self.scan.findings.push(finding(
                    Rule::PostgresOutboxSettlementFunnel,
                    format!("{}:{line}", self.path.display()),
                    format!(
                        "PG-OUTBOX-SETTLEMENT-FUNNEL-01 raw function `{function}` 只能在 `{POSTGRES_OUTBOX_SETTLEMENT_PATH}` 执行"
                    ),
                ));
            }
        }
    }

    fn scoped_sql(
        scopes: &[BTreeMap<String, ResolvedSettlementSql>],
        name: &str,
    ) -> Option<ResolvedSettlementSql> {
        scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
    }

    fn resolve_sql(&self, expression: &syn::Expr) -> Option<ResolvedSettlementSql> {
        if let Some(sql) = expr_string_literal(expression) {
            return Some(ResolvedSettlementSql {
                value: sql.value(),
                line: sql.span().start().line,
            });
        }
        if let Some(name) = simple_expr_ident(expression)
            && let Some(sql) = Self::scoped_sql(&self.bindings, &name)
        {
            return Some(sql);
        }
        if let Some(function) = typed_outbox_routine_function(expression, self.callable_functions) {
            return Some(ResolvedSettlementSql {
                value: format!("SELECT {function}($1)"),
                line: expression.span().start().line,
            });
        }
        let syn::Expr::Macro(expression) = peel_expr(expression) else {
            return None;
        };
        if !path_ends_with(&expression.mac.path, "concat") {
            return None;
        }
        let expressions = parse_macro_expressions(&expression.mac.tokens)?;
        let mut value = String::new();
        for part in expressions {
            value.push_str(&self.resolve_sql(&part)?.value);
        }
        Some(ResolvedSettlementSql {
            value,
            line: expression.mac.span().start().line,
        })
    }

    fn query_sql(&self, expression: &syn::Expr) -> Option<ResolvedSettlementSql> {
        match peel_expr(expression) {
            syn::Expr::MethodCall(call) => self.query_sql(&call.receiver),
            syn::Expr::Call(call) => {
                let syn::Expr::Path(function) = peel_expr(&call.func) else {
                    return None;
                };
                sqlx_query_path(&function.path).then(|| {
                    call.args
                        .iter()
                        .find_map(|argument| self.resolve_sql(argument))
                })?
            }
            syn::Expr::Macro(expression) if sqlx_query_path(&expression.mac.path) => {
                parse_macro_expressions(&expression.mac.tokens)?
                    .iter()
                    .find_map(|argument| self.resolve_sql(argument))
            }
            syn::Expr::Path(_) => {
                let name = simple_expr_ident(expression)?;
                Self::scoped_sql(&self.builders, &name)
            }
            _ => None,
        }
    }

    fn inspect_awaited_expression(&mut self, expression: &syn::Expr) {
        if let Some(receiver) = awaited_sqlx_terminal_receiver(expression)
            && let Some(sql) = self.query_sql(receiver)
        {
            self.inspect_sql(&sql.value, sql.line);
            return;
        }

        let syn::Expr::Call(call) = peel_expr(expression) else {
            return;
        };
        let syn::Expr::Path(function) = peel_expr(&call.func) else {
            return;
        };
        let Some(name) = function.path.get_ident().map(ToString::to_string) else {
            return;
        };
        let Some(arguments) = self.local_executor_arguments.get(&name).cloned() else {
            return;
        };
        for index in arguments {
            if let Some(sql) = call
                .args
                .iter()
                .nth(index)
                .and_then(|argument| self.resolve_sql(argument))
            {
                self.inspect_sql(&sql.value, sql.line);
            }
        }
    }
}

fn typed_outbox_routine_function<'a>(
    expression: &syn::Expr,
    callable_functions: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let syn::Expr::MethodCall(call) = peel_expr(expression) else {
        return None;
    };
    if call.method != "sql" || !call.args.is_empty() {
        return None;
    }
    let syn::Expr::Path(receiver) = peel_expr(&call.receiver) else {
        return None;
    };
    let segments = receiver
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if segments.len() != 4
        || segments[0] != "crate"
        || segments[1] != "outbox_routine"
        || segments[2] != "OutboxCallableRoutine"
    {
        return None;
    }
    callable_functions.get(&segments[3]).map(String::as_str)
}

fn outbox_callable_catalog(sources: &[(PathBuf, String)]) -> BTreeMap<String, String> {
    let Some((_, source)) = sources
        .iter()
        .find(|(path, _)| path == Path::new(POSTGRES_OUTBOX_ROUTINE_CATALOG_PATH))
    else {
        return BTreeMap::new();
    };
    parse_outbox_callable_catalog(source)
}

pub(crate) fn parse_outbox_callable_catalog(source: &str) -> BTreeMap<String, String> {
    use proc_macro2::{Delimiter, TokenTree};

    let Ok(file) = syn::parse_file(source) else {
        return BTreeMap::new();
    };
    let Some(invocation) = file.items.iter().find_map(|item| match item {
        syn::Item::Macro(item) if path_ends_with(&item.mac.path, "outbox_routine_catalog") => {
            Some(&item.mac)
        }
        _ => None,
    }) else {
        return BTreeMap::new();
    };
    let tokens = invocation.tokens.clone().into_iter().collect::<Vec<_>>();
    let mut catalog = BTreeMap::new();
    for index in 0..tokens.len().saturating_sub(1) {
        let TokenTree::Ident(section) = &tokens[index] else {
            continue;
        };
        if section != "serving" && section != "operator" {
            continue;
        }
        let TokenTree::Group(entries) = &tokens[index + 1] else {
            continue;
        };
        if entries.delimiter() != Delimiter::Brace {
            continue;
        }
        let entries = entries.stream().into_iter().collect::<Vec<_>>();
        for entry_index in 0..entries.len().saturating_sub(2) {
            let (TokenTree::Ident(variant), TokenTree::Punct(eq), TokenTree::Punct(gt)) = (
                &entries[entry_index],
                &entries[entry_index + 1],
                &entries[entry_index + 2],
            ) else {
                continue;
            };
            if eq.as_char() != '=' || gt.as_char() != '>' {
                continue;
            }
            let Some(TokenTree::Group(fields)) = entries.get(entry_index + 3) else {
                continue;
            };
            let fields = fields.stream().into_iter().collect::<Vec<_>>();
            for field_index in 0..fields.len().saturating_sub(2) {
                let (TokenTree::Ident(label), TokenTree::Punct(colon), TokenTree::Ident(function)) = (
                    &fields[field_index],
                    &fields[field_index + 1],
                    &fields[field_index + 2],
                ) else {
                    continue;
                };
                if label == "function" && colon.as_char() == ':' {
                    catalog.insert(variant.to_string(), function.to_string());
                    break;
                }
            }
        }
    }
    catalog
}

impl<'ast> Visit<'ast> for SettlementSqlVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_claim_test_only(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !is_claim_test_only(&node.attrs) {
            self.bindings.push(BTreeMap::new());
            self.builders.push(BTreeMap::new());
            syn::visit::visit_item_fn(self, node);
            self.builders.pop();
            self.bindings.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !is_claim_test_only(&node.attrs) {
            self.bindings.push(BTreeMap::new());
            self.builders.push(BTreeMap::new());
            syn::visit::visit_impl_item_fn(self, node);
            self.builders.pop();
            self.bindings.pop();
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (Some(name), Some(init)) = (pat_ident(&node.pat), node.init.as_ref()) {
            if let Some(sql) = self.resolve_sql(&init.expr)
                && let Some(scope) = self.bindings.last_mut()
            {
                scope.insert(name.clone(), sql);
            }
            if let Some(sql) = self.query_sql(&init.expr)
                && let Some(scope) = self.builders.last_mut()
            {
                scope.insert(name, sql);
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
        self.inspect_awaited_expression(&node.base);
        syn::visit::visit_expr_await(self, node);
    }
}

fn static_string_bindings(file: &syn::File) -> BTreeMap<String, ResolvedSettlementSql> {
    #[derive(Default)]
    struct Collector(BTreeMap<String, ResolvedSettlementSql>);

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if !is_claim_test_only(&node.attrs) {
                syn::visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
            if !is_claim_test_only(&node.attrs)
                && let Some(sql) = expr_string_literal(&node.expr)
            {
                self.0.insert(
                    node.ident.to_string(),
                    ResolvedSettlementSql {
                        value: sql.value(),
                        line: sql.span().start().line,
                    },
                );
            }
        }

        fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
            if !is_claim_test_only(&node.attrs)
                && let Some(sql) = expr_string_literal(&node.expr)
            {
                self.0.insert(
                    node.ident.to_string(),
                    ResolvedSettlementSql {
                        value: sql.value(),
                        line: sql.span().start().line,
                    },
                );
            }
        }
    }

    let mut collector = Collector::default();
    collector.visit_file(file);
    collector.0
}

fn parse_macro_expressions(
    tokens: &proc_macro2::TokenStream,
) -> Option<syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>> {
    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .ok()
}

fn path_ends_with(path: &syn::Path, expected: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == expected)
}

fn awaited_sqlx_terminal_receiver(expression: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::MethodCall(call) = peel_expr(expression) else {
        return None;
    };
    matches!(
        call.method.to_string().as_str(),
        "execute"
            | "execute_many"
            | "fetch"
            | "fetch_many"
            | "fetch_all"
            | "fetch_one"
            | "fetch_optional"
    )
    .then_some(call.receiver.as_ref())
}

fn local_settlement_executor_arguments(file: &syn::File) -> BTreeMap<String, BTreeSet<usize>> {
    let mut executors = BTreeMap::new();
    for item in &file.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        let parameters = function
            .sig
            .inputs
            .iter()
            .filter_map(|input| match input {
                syn::FnArg::Typed(argument) => pat_ident(&argument.pat),
                syn::FnArg::Receiver(_) => None,
            })
            .enumerate()
            .map(|(index, name)| (name, index))
            .collect::<BTreeMap<_, _>>();
        let mut visitor = ExecutedSqlParameterVisitor {
            parameters: parameters.keys().cloned().collect(),
            executed: BTreeSet::new(),
        };
        visitor.visit_block(&function.block);
        let arguments = visitor
            .executed
            .into_iter()
            .filter_map(|name| parameters.get(&name).copied())
            .collect::<BTreeSet<_>>();
        if !arguments.is_empty() {
            executors.insert(function.sig.ident.to_string(), arguments);
        }
    }
    executors
}

struct ExecutedSqlParameterVisitor {
    parameters: BTreeSet<String>,
    executed: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ExecutedSqlParameterVisitor {
    fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
        if let Some(receiver) = awaited_sqlx_terminal_receiver(&node.base)
            && let Some(argument) = sqlx_query_argument(receiver)
            && let Some(name) = simple_expr_ident(argument)
            && self.parameters.contains(&name)
        {
            self.executed.insert(name);
        }
        syn::visit::visit_expr_await(self, node);
    }
}

fn sqlx_query_argument(expression: &syn::Expr) -> Option<&syn::Expr> {
    match peel_expr(expression) {
        syn::Expr::MethodCall(call) => sqlx_query_argument(&call.receiver),
        syn::Expr::Call(call) => {
            let syn::Expr::Path(function) = peel_expr(&call.func) else {
                return None;
            };
            sqlx_query_path(&function.path).then(|| call.args.first())?
        }
        _ => None,
    }
}

fn raw_settlement_function_calls(sql: &str) -> BTreeSet<String> {
    direct_sql_statements(sql)
        .into_iter()
        .flat_map(|statement| settlement_function_identifiers(&statement.text))
        .collect()
}

fn settlement_function_identifiers(statement: &str) -> BTreeSet<String> {
    let statement = statement.as_bytes();
    let mut functions = BTreeSet::new();
    let mut cursor = 0;
    while cursor < statement.len() {
        if !is_sql_ident_byte(statement[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while statement
            .get(cursor)
            .is_some_and(|byte| is_sql_ident_byte(*byte))
        {
            cursor += 1;
        }
        let mut after = cursor;
        while statement.get(after).is_some_and(u8::is_ascii_whitespace) {
            after += 1;
        }
        let identifier = String::from_utf8_lossy(&statement[start..cursor]).to_ascii_lowercase();
        if statement.get(after) == Some(&b'(')
            && (identifier.starts_with("rss_outbox_settle_") || identifier == "rss_outbox_mark_dlx")
        {
            functions.insert(identifier);
        }
    }
    functions
}

fn is_sql_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn scan_relay_budget_sources(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let source_map = sources
        .iter()
        .map(|(path, content)| (path.as_path(), content.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    for (path, required) in [
        (
            "crates/eventexec/src/relay_config.rs",
            &["pub const RELAY_BUDGET_MAX_MILLIS: u64 = 86_400_000"][..],
        ),
        (
            "assemblies/runtime/src/event_transport.rs",
            &[
                "relay: RelayTiming",
                "budget: RelayBudget",
                "const RELAY_LEASE_TTL_ENV: &str = \"RSS_RELAY_LEASE_TTL_MS\"",
                "const RELAY_PUBLISH_TIMEOUT_ENV: &str = \"RSS_RELAY_PUBLISH_TIMEOUT_MS\"",
                "const RELAY_SETTLE_TIMEOUT_ENV: &str = \"RSS_RELAY_SETTLE_TIMEOUT_MS\"",
                "const RELAY_SAFETY_MARGIN_ENV: &str = \"RSS_RELAY_SAFETY_MARGIN_MS\"",
            ][..],
        ),
        (
            "adapters/amqp/src/publisher.rs",
            &[
                "const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_000",
                "publish_timeout: Duration",
            ][..],
        ),
        (
            "adapters/amqp/src/bundle.rs",
            &["publish_timeout: Duration"][..],
        ),
        (
            "adapters/postgres/src/outbox.rs",
            &["relay_budget: RelayBudget"][..],
        ),
        (
            "adapters/postgres/src/bundle.rs",
            &["relay_budget: RelayBudget"][..],
        ),
        (
            "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
            &[
                "rss_outbox_claim_batch(text, bigint, bigint, bigint)",
                "rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint)",
                "p_required_budget_ms >= p_lease_ttl_ms",
                "p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000",
                "p_required_budget_ms * interval",
                "DROP FUNCTION rss_outbox_claim_batch(text, bigint)",
                "DROP FUNCTION rss_outbox_publish_preflight(text, uuid, bigint)",
            ][..],
        ),
    ] {
        let content = source_map.get(Path::new(path)).copied().unwrap_or_default();
        let structural = if path.ends_with(".rs") {
            production_rust_structure(content).unwrap_or_default()
        } else {
            relay_budget_sql_code(content)
        };
        for fragment in required {
            let normalized = fragment
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if !structural.contains(&normalized) {
                findings.push(finding(
                    Rule::OutboxRelayBudget,
                    path.to_string(),
                    format!("OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `{fragment}`"),
                ));
            }
        }
    }
    findings.extend(scan_relay_budget_live_seams(&source_map));
    if let Some(content) = source_map.get(Path::new("adapters/amqp/src/publisher.rs")) {
        findings.extend(scan_amqp_publish_bypass(content));
    }
    if let Some(content) = source_map.get(Path::new("adapters/amqp/src/conn.rs")) {
        findings.extend(scan_amqp_connection_recovery_owner(content));
    }

    // Boundary tests are part of the Medium gate: parse the complete Rust token stream so comments
    // cannot satisfy these anchors, while retaining cfg(test) bodies and SQL macro literals.
    for (path, required) in [
        (
            "crates/eventexec/src/relay_config.rs",
            &[
                "fn relay_budget_operational_ceiling_is_inclusive_and_public",
                "RELAY_BUDGET_MAX_MILLIS + 1",
            ][..],
        ),
        (
            "assemblies/runtime/src/event_transport.rs",
            &[
                "fn event_worker_snapshot_relay_budget_invalid_values_fail_fast",
                "(\"RSS_RELAY_LEASE_TTL_MS\", \"86400001\")",
            ][..],
        ),
        (
            "adapters/amqp/src/publisher.rs",
            &["MAX_PUBLISH_TIMEOUT_MILLIS + 1"][..],
        ),
        (
            "adapters/postgres/src/outbox.rs",
            &["fn relay_budget_migration_is_parameterized_breaking_and_least_privilege"][..],
        ),
        (
            POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH,
            &[
                "fn relay_budget_sql_boundary_is_fail_closed_and_claim_uses_configured_ttl",
                "Some(86_400_001)",
            ][..],
        ),
    ] {
        let content = source_map.get(Path::new(path)).copied().unwrap_or_default();
        let structure = syn::parse_file(content)
            .map(|file| normalized_tokens(&file))
            .unwrap_or_default();
        for fragment in required {
            let normalized = fragment
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if !structure.contains(&normalized) {
                findings.push(finding(
                    Rule::OutboxRelayBudget,
                    path.to_string(),
                    format!("OUTBOX-RELAY-BUDGET-01 缺边界测试 fragment `{fragment}`"),
                ));
            }
        }
    }
    for (path, content) in sources {
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && path != Path::new("crates/eventexec/src/relay_config.rs")
            && path != Path::new(POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH)
        {
            findings.extend(scan_hardcoded_relay_budget(path, content));
        }
    }
    for (path, marker, function, required) in [
        (
            "assemblies/runtime/src/phase/infra.rs",
            "runtime event transport budget loaded",
            Some("ProvidersBuilt::build_infra"),
            &[
                "runtime.event_topology",
                "relay.lease_ttl_ms",
                "relay.publish_timeout_ms",
                "relay.settle_timeout_ms",
                "relay.safety_margin_ms",
                "relay.required_budget_ms",
            ][..],
        ),
        (
            "adapters/amqp/src/publisher.rs",
            "amqp publish outcome is ambiguous",
            None,
            &[
                "phase",
                "publish_timeout_ms",
                "delivery_outcome",
                "broker_may_have_received",
            ][..],
        ),
        (
            "adapters/postgres/src/outbox.rs",
            "outbox publisher watchdog timed out",
            Some("with_publisher_watchdog"),
            &[
                "phase",
                "publish_timeout_ms",
                "publisher_watchdog_timeout_ms",
                "delivery_outcome",
                "broker_may_have_received",
            ][..],
        ),
        (
            "adapters/postgres/src/outbox/settlement.rs",
            "outbox settlement timed out",
            Some("settlement_timeout_error"),
            &[
                "phase",
                "settle_timeout_ms",
                "delivery_outcome",
                "broker_may_have_received",
            ][..],
        ),
    ] {
        let content = source_map.get(Path::new(path)).copied().unwrap_or_default();
        findings.extend(scan_relay_budget_audit(
            path, content, marker, function, required,
        ));
    }
    findings
}

fn scan_amqp_publish_bypass(content: &str) -> Vec<Finding<Rule>> {
    const PATH: &str = "adapters/amqp/src/publisher.rs";
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            "AMQP-PUBLISH-BYPASS-01 carrier Rust AST 无法解析".to_string(),
        )];
    };
    // Shared production callable collection finds the unique Publisher::publish owner and any
    // publish-local nested callables that are lexically reachable from it. Uncalled dead nested
    // declarations stay out of the residual surface; helper/pipeline names, local order, and
    // AmqpPublisher sibling method bodies outside publish are not locked (Ambiguous⇒retire is
    // owned by Hard decision types + enrolled ambiguity provider behavior).
    let mut collection = AmqpCallableCollection::default();
    collect_amqp_production_callables(&file.items, "", &mut collection);
    let publish_methods = collection
        .callables
        .iter()
        .filter(|callable| callable.is_impl_method("AmqpPublisher", Some("Publisher"), "publish"))
        .collect::<Vec<_>>();
    if publish_methods.len() != 1 {
        return vec![finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            "AMQP-PUBLISH-BYPASS-01 缺唯一 AmqpPublisher::publish production owner".to_string(),
        )];
    }
    let publish = publish_methods[0];
    let publish_label = publish.label();
    let publish_scope = amqp_callable_scope("", &publish_label);
    let nested_prefix = format!("{publish_scope}::lexical-scope#");
    let mut findings = collection
        .resolution_issues
        .iter()
        .filter(|issue| issue.starts_with(&format!("`{publish_scope}` ")))
        .map(|issue| {
            finding(
                Rule::AmqpPublishBypass,
                PATH.to_string(),
                format!("AMQP-PUBLISH-BYPASS-01 {issue}"),
            )
        })
        .collect::<Vec<_>>();
    let mut visitor = AmqpPublishBypassVisitor::default();
    visitor.visit_block(publish.block);
    for callable in &collection.callables {
        if callable.module.starts_with(&nested_prefix) {
            visitor.nested_callable_depth += 1;
            visitor.visit_block(callable.block);
            visitor.nested_callable_depth -= 1;
        }
    }
    if !visitor.publisher_error_constructors.is_empty() {
        findings.push(finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            format!(
                "AMQP-PUBLISH-BYPASS-01 Publisher::publish 禁止直接构造 PublisherError: {:?}",
                visitor.publisher_error_constructors
            ),
        ));
    }
    if visitor.retires_transport {
        findings.push(finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            "AMQP-PUBLISH-BYPASS-01 Publisher::publish 禁止直接 retire_transport".to_string(),
        ));
    }
    if visitor.try_expressions != 0 {
        findings.push(finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            format!(
                "AMQP-PUBLISH-BYPASS-01 Publisher::publish 有 {} 个外层 `?` 可绕过 typed failure decision",
                visitor.try_expressions
            ),
        ));
    }
    if visitor.sensitive_macro {
        findings.push(finding(
            Rule::AmqpPublishBypass,
            PATH.to_string(),
            "AMQP-PUBLISH-BYPASS-01 Publisher::publish 禁止用 macro 隐藏 PublisherError/retire_transport"
                .to_string(),
        ));
    }
    findings
}

#[derive(Default)]
struct AmqpPublishBypassVisitor {
    publisher_error_constructors: BTreeSet<String>,
    retires_transport: bool,
    try_expressions: usize,
    sensitive_macro: bool,
    nested_callable_depth: usize,
}

/// Sensitive `PublisherError` constructor terminal names shared by call-callee and macro token
/// surfaces so Medium residual does not maintain a second closed set.
const PUBLISHER_ERROR_SENSITIVE_CONSTRUCTORS: &[&str] = &["transient", "permanent", "ambiguous"];

fn is_rust_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn macro_tokens_contain_publisher_error_constructor(tokens: &str) -> bool {
    PUBLISHER_ERROR_SENSITIVE_CONSTRUCTORS.iter().any(|name| {
        if tokens.contains(&format!("PublisherError::{name}")) {
            return true;
        }
        let needle = format!("{name}(");
        let mut from = 0;
        while let Some(rel) = tokens[from..].find(&needle) {
            let at = from + rel;
            let bare = at == 0 || !is_rust_ident_continue(tokens.as_bytes()[at - 1]);
            if bare {
                return true;
            }
            from = at + 1;
        }
        false
    })
}

impl AmqpPublishBypassVisitor {
    fn note_publisher_error_path(&mut self, path: &syn::Path) {
        let mut segments = path.segments.iter().rev();
        let Some(last) = segments.next() else {
            return;
        };
        let constructor = last.ident.to_string();
        if !PUBLISHER_ERROR_SENSITIVE_CONSTRUCTORS.contains(&constructor.as_str()) {
            return;
        }
        if segments
            .next()
            .is_some_and(|segment| segment.ident == "PublisherError")
        {
            self.publisher_error_constructors.insert(constructor);
        }
    }

    fn note_publisher_error_call_callee(&mut self, path: &syn::Path) {
        let Some(last) = path.segments.last() else {
            return;
        };
        let constructor = last.ident.to_string();
        if PUBLISHER_ERROR_SENSITIVE_CONSTRUCTORS.contains(&constructor.as_str()) {
            self.publisher_error_constructors.insert(constructor);
        }
    }
}

impl<'ast> Visit<'ast> for AmqpPublishBypassVisitor {
    // Nested item declarations are resolved via publish-local reachability, not the live walk.
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_expr_async(&mut self, node: &'ast syn::ExprAsync) {
        self.nested_callable_depth += 1;
        syn::visit::visit_expr_async(self, node);
        self.nested_callable_depth -= 1;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nested_callable_depth += 1;
        syn::visit::visit_expr_closure(self, node);
        self.nested_callable_depth -= 1;
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = peel_expr(&node.func) {
            self.note_publisher_error_call_callee(&path.path);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "retire_transport" {
            self.retires_transport = true;
        }
        // UFCS-style path receivers are handled via visit_expr_path on nested nodes.
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let mut segments = node.path.segments.iter().rev();
        if segments
            .next()
            .is_some_and(|segment| segment.ident == "retire_transport")
        {
            self.retires_transport = true;
        }
        self.note_publisher_error_path(&node.path);
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        if self.nested_callable_depth == 0 {
            self.try_expressions += 1;
        }
        syn::visit::visit_expr_try(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let tokens = normalized_tokens(node);
        self.sensitive_macro |= tokens.contains("retire_transport")
            || macro_tokens_contain_publisher_error_constructor(&tokens);
        syn::visit::visit_macro(self, node);
    }
}

enum AmqpCallableOwner {
    Free,
    Impl {
        self_type: String,
        trait_name: Option<String>,
    },
    TraitDefault {
        trait_name: String,
    },
}

struct AmqpProductionCallable<'a> {
    module: String,
    name: String,
    owner: AmqpCallableOwner,
    block: &'a syn::Block,
}

#[derive(Default)]
struct AmqpCallableCollection<'a> {
    callables: Vec<AmqpProductionCallable<'a>>,
    resolution_issues: Vec<String>,
}

impl AmqpProductionCallable<'_> {
    fn is_impl_method(&self, self_type: &str, trait_name: Option<&str>, name: &str) -> bool {
        self.name == name
            && matches!(
                &self.owner,
                AmqpCallableOwner::Impl {
                    self_type: actual_self_type,
                    trait_name: actual_trait,
                } if actual_self_type == self_type && actual_trait.as_deref() == trait_name
            )
    }

    fn is_root_free(&self, name: &str) -> bool {
        self.module.is_empty() && self.name == name && matches!(self.owner, AmqpCallableOwner::Free)
    }

    fn label(&self) -> String {
        let owner = match &self.owner {
            AmqpCallableOwner::Free => self.module.clone(),
            AmqpCallableOwner::Impl {
                self_type,
                trait_name,
            } => trait_name.as_ref().map_or_else(
                || self_type.clone(),
                |name| format!("{name} for {self_type}"),
            ),
            AmqpCallableOwner::TraitDefault { trait_name } => trait_name.clone(),
        };
        if owner.is_empty() {
            self.name.clone()
        } else {
            format!("{owner}::{}", self.name)
        }
    }
}

fn collect_amqp_production_callables<'a>(
    items: &'a [syn::Item],
    module: &str,
    collection: &mut AmqpCallableCollection<'a>,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) if !has_test_attr(&function.attrs) => {
                collection.callables.push(AmqpProductionCallable {
                    module: module.to_string(),
                    name: function.sig.ident.to_string(),
                    owner: AmqpCallableOwner::Free,
                    block: &function.block,
                });
                let scope = amqp_callable_scope(module, &function.sig.ident.to_string());
                collect_reachable_amqp_local_functions(&function.block, &scope, collection);
            }
            syn::Item::Impl(item_impl) if !has_test_attr(&item_impl.attrs) => {
                let self_type = normalized_tokens(&item_impl.self_ty);
                let trait_name = item_impl.trait_.as_ref().and_then(|(_, path, _)| {
                    path.segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                });
                for item in &item_impl.items {
                    let syn::ImplItem::Fn(function) = item else {
                        continue;
                    };
                    if has_test_attr(&function.attrs) {
                        continue;
                    }
                    collection.callables.push(AmqpProductionCallable {
                        module: module.to_string(),
                        name: function.sig.ident.to_string(),
                        owner: AmqpCallableOwner::Impl {
                            self_type: self_type.clone(),
                            trait_name: trait_name.clone(),
                        },
                        block: &function.block,
                    });
                    let owner = trait_name.as_ref().map_or_else(
                        || self_type.clone(),
                        |name| format!("{name} for {self_type}"),
                    );
                    let scope =
                        amqp_callable_scope(module, &format!("{owner}::{}", function.sig.ident));
                    collect_reachable_amqp_local_functions(&function.block, &scope, collection);
                }
            }
            syn::Item::Trait(item_trait) if !has_test_attr(&item_trait.attrs) => {
                let trait_name = item_trait.ident.to_string();
                for item in &item_trait.items {
                    let syn::TraitItem::Fn(function) = item else {
                        continue;
                    };
                    let Some(block) = function.default.as_ref() else {
                        continue;
                    };
                    if has_test_attr(&function.attrs) {
                        continue;
                    }
                    collection.callables.push(AmqpProductionCallable {
                        module: module.to_string(),
                        name: function.sig.ident.to_string(),
                        owner: AmqpCallableOwner::TraitDefault {
                            trait_name: trait_name.clone(),
                        },
                        block,
                    });
                    let scope = amqp_callable_scope(
                        module,
                        &format!("{trait_name}::{}", function.sig.ident),
                    );
                    collect_reachable_amqp_local_functions(block, &scope, collection);
                }
            }
            syn::Item::Mod(item_mod) if !has_test_attr(&item_mod.attrs) => {
                if let Some((_, nested)) = &item_mod.content {
                    let nested_name = item_mod.ident.to_string();
                    let nested_module = if module.is_empty() {
                        nested_name
                    } else {
                        format!("{module}::{nested_name}")
                    };
                    collect_amqp_production_callables(nested, &nested_module, collection);
                }
            }
            _ => {}
        }
    }
}

fn amqp_callable_scope(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}::{name}")
    }
}

/// Collect block-local functions only when a reachable lexical scope references them. The graph
/// preserves dead declaration bait while closing direct-call, function-item alias, nested block,
/// `if`, and `match` bypasses. Name resolution follows the nearest lexical scope and fails closed
/// when a reachable scope contains duplicate local function declarations.
fn collect_reachable_amqp_local_functions<'a>(
    block: &'a syn::Block,
    scope: &str,
    collection: &mut AmqpCallableCollection<'a>,
) {
    let graph = AmqpLocalCallableGraph::build(block);
    let (reachable, issues) = graph.resolve_reachable();
    collection
        .resolution_issues
        .extend(issues.into_iter().map(|issue| format!("`{scope}` {issue}")));
    for function_id in reachable {
        let function = &graph.functions[function_id];
        collection.callables.push(AmqpProductionCallable {
            module: format!("{scope}::lexical-scope#{}", function.declared_scope),
            name: function.function.sig.ident.to_string(),
            owner: AmqpCallableOwner::Free,
            block: &function.function.block,
        });
    }
}

struct AmqpLocalCallableGraph<'a> {
    scopes: Vec<AmqpLexicalScope>,
    functions: Vec<AmqpLocalFunction<'a>>,
}

impl<'a> AmqpLocalCallableGraph<'a> {
    fn build(block: &'a syn::Block) -> Self {
        let mut builder = AmqpLocalCallableGraphBuilder {
            graph: Self {
                scopes: Vec::new(),
                functions: Vec::new(),
            },
            current_scope: None,
            current_owner: None,
        };
        builder.collect_block(block, None, None);
        builder.graph
    }

    fn resolve_reachable(&self) -> (BTreeSet<usize>, BTreeSet<String>) {
        let mut reachable = BTreeSet::new();
        let mut issues = BTreeSet::new();
        loop {
            let mut discovered = BTreeSet::new();
            for (scope_id, lexical_scope) in self.scopes.iter().enumerate() {
                if lexical_scope
                    .owner
                    .is_some_and(|owner| !reachable.contains(&owner))
                {
                    continue;
                }
                for (name, declarations) in &lexical_scope.declarations {
                    if declarations.len() != 1 {
                        issues.insert(format!(
                            "lexical-scope#{scope_id} 的 local callable `{name}` provenance 不唯一（{} 个声明）",
                            declarations.len()
                        ));
                    }
                }
                for reference in &lexical_scope.references {
                    match self.resolve_reference(scope_id, reference) {
                        Ok(Some(function_id)) if !reachable.contains(&function_id) => {
                            discovered.insert(function_id);
                        }
                        Ok(_) => {}
                        Err(issue) => {
                            issues.insert(issue);
                        }
                    }
                }
            }
            if discovered.is_empty() {
                break;
            }
            reachable.extend(discovered);
        }
        (reachable, issues)
    }

    fn resolve_reference(
        &self,
        mut scope_id: usize,
        name: &str,
    ) -> std::result::Result<Option<usize>, String> {
        loop {
            let lexical_scope = &self.scopes[scope_id];
            if let Some(declarations) = lexical_scope.declarations.get(name) {
                return match declarations.as_slice() {
                    [function_id] => Ok(Some(*function_id)),
                    _ => Err(format!(
                        "lexical-scope#{scope_id} 无法唯一解析 local callable `{name}`"
                    )),
                };
            }
            let Some(parent) = lexical_scope.parent else {
                return Ok(None);
            };
            scope_id = parent;
        }
    }
}

#[derive(Default)]
struct AmqpLexicalScope {
    parent: Option<usize>,
    owner: Option<usize>,
    declarations: BTreeMap<String, Vec<usize>>,
    references: BTreeSet<String>,
}

struct AmqpLocalFunction<'a> {
    function: &'a syn::ItemFn,
    declared_scope: usize,
}

struct AmqpLocalCallableGraphBuilder<'a> {
    graph: AmqpLocalCallableGraph<'a>,
    current_scope: Option<usize>,
    current_owner: Option<usize>,
}

impl<'a> AmqpLocalCallableGraphBuilder<'a> {
    fn collect_block(
        &mut self,
        block: &'a syn::Block,
        parent: Option<usize>,
        owner: Option<usize>,
    ) -> usize {
        let scope_id = self.graph.scopes.len();
        self.graph.scopes.push(AmqpLexicalScope {
            parent,
            owner,
            ..Default::default()
        });

        let mut declared = Vec::new();
        for statement in &block.stmts {
            let syn::Stmt::Item(syn::Item::Fn(function)) = statement else {
                continue;
            };
            if has_test_attr(&function.attrs) {
                continue;
            }
            let function_id = self.graph.functions.len();
            self.graph.functions.push(AmqpLocalFunction {
                function,
                declared_scope: scope_id,
            });
            self.graph.scopes[scope_id]
                .declarations
                .entry(function.sig.ident.to_string())
                .or_default()
                .push(function_id);
            declared.push(function_id);
        }

        for function_id in declared {
            let function = self.graph.functions[function_id].function;
            self.collect_block(&function.block, Some(scope_id), Some(function_id));
        }

        let previous_scope = self.current_scope.replace(scope_id);
        let previous_owner = self.current_owner;
        self.current_owner = owner;
        for statement in &block.stmts {
            if !matches!(statement, syn::Stmt::Item(_)) {
                syn::visit::visit_stmt(self, statement);
            }
        }
        self.current_scope = previous_scope;
        self.current_owner = previous_owner;
        scope_id
    }
}

impl<'ast> Visit<'ast> for AmqpLocalCallableGraphBuilder<'ast> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_block(&mut self, node: &'ast syn::Block) {
        if let Some(parent) = self.current_scope {
            self.collect_block(node, Some(parent), self.current_owner);
        }
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.qself.is_none()
            && node.path.leading_colon.is_none()
            && node.path.segments.len() == 1
            && let Some(scope_id) = self.current_scope
            && let Some(segment) = node.path.segments.last()
        {
            self.graph.scopes[scope_id]
                .references
                .insert(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, node);
    }
}

fn scan_amqp_connection_recovery_owner(content: &str) -> Vec<Finding<Rule>> {
    const PATH: &str = "adapters/amqp/src/conn.rs";
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::AmqpRecoveryOwner,
            PATH.to_string(),
            "AMQP-RSS-RECOVERY-OWNER-01 carrier Rust AST 无法解析".to_string(),
        )];
    };
    let mut collection = AmqpCallableCollection::default();
    collect_amqp_production_callables(&file.items, "", &mut collection);
    let mut findings = collection
        .resolution_issues
        .iter()
        .map(|issue| {
            finding(
                Rule::AmqpRecoveryOwner,
                PATH.to_string(),
                format!("AMQP-RSS-RECOVERY-OWNER-01 {issue}"),
            )
        })
        .collect::<Vec<_>>();
    let facts = collection
        .callables
        .iter()
        .map(|callable| {
            let mut calls = AmqpConnectionCalls::default();
            calls.visit_block(callable.block);
            (callable, calls)
        })
        .collect::<Vec<_>>();
    findings.extend(scan_amqp_connection_sensitive_calls(&facts, PATH));
    findings.extend(validate_amqp_connection_entry(
        &facts,
        PATH,
        "connect_with_private_ca",
        |context| context == "ConnectContext::Initial",
    ));
    findings.extend(validate_amqp_connection_entry(
        &facts,
        PATH,
        "reconnect_publisher",
        |context| context.starts_with("ConnectContext::Recovery{"),
    ));
    findings
}

fn scan_amqp_connection_sensitive_calls(
    facts: &[(&AmqpProductionCallable<'_>, AmqpConnectionCalls)],
    path: &str,
) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    let mut connection_calls = 0;
    let mut property_factories = 0;
    for (callable, calls) in facts {
        if calls.auto_recover || calls.sensitive_macro {
            findings.push(finding(
                Rule::AmqpRecoveryOwner,
                path.to_string(),
                format!(
                    "AMQP-RSS-RECOVERY-OWNER-01 production callable `{}` 禁止 Lapin auto-recovery/macro indirection",
                    callable.label()
                ),
            ));
        }
        connection_calls += calls.connection_properties.len();
        property_factories += calls.property_factories.len();
        if calls.nested_connection_owner {
            findings.push(finding(
                Rule::AmqpRecoveryOwner,
                path.to_string(),
                format!(
                    "AMQP-RSS-RECOVERY-OWNER-01 `{}` 不得把 Connection::connect 隐藏在 nested callable",
                    callable.label()
                ),
            ));
        }
        for properties in &calls.connection_properties {
            if !callable.is_root_free("connect_with_context")
                && !callable.is_root_free("connect_with_exclusive_private_ca")
                || properties != "ConnectionProperties::default()"
            {
                findings.push(finding(
                    Rule::AmqpRecoveryOwner,
                    path.to_string(),
                    format!(
                        "AMQP-RSS-RECOVERY-OWNER-01 `{}` 的 Connection::connect 必须由 connect_with_context 以 ConnectionProperties::default() 调用；实际 properties=`{properties}`",
                        callable.label()
                    ),
                ));
            }
        }
        for factory in &calls.property_factories {
            if factory != "default" {
                findings.push(finding(
                    Rule::AmqpRecoveryOwner,
                    path.to_string(),
                    format!(
                        "AMQP-RSS-RECOVERY-OWNER-01 `{}` 使用非 canonical ConnectionProperties::{factory}",
                        callable.label()
                    ),
                ));
            }
        }
        if calls.custom_properties {
            findings.push(finding(
                Rule::AmqpRecoveryOwner,
                path.to_string(),
                format!(
                    "AMQP-RSS-RECOVERY-OWNER-01 `{}` 禁止直接构造 ConnectionProperties",
                    callable.label()
                ),
            ));
        }
        if !calls.context_calls.is_empty()
            && !callable.is_root_free("connect")
            && !callable.is_root_free("connect_with_private_ca")
            && !callable.is_root_free("reconnect_publisher")
        {
            findings.push(finding(
                Rule::AmqpRecoveryOwner,
                path.to_string(),
                format!(
                    "AMQP-RSS-RECOVERY-OWNER-01 `{}` 无权调用 connect_with_context",
                    callable.label()
                ),
            ));
        }
    }
    if connection_calls != 2 {
        findings.push(finding(
            Rule::AmqpRecoveryOwner,
            path.to_string(),
            format!(
                "AMQP-RSS-RECOVERY-OWNER-01 必须且只能有两个显式连接 owner；实际 {connection_calls}"
            ),
        ));
    }
    if property_factories != 2 {
        findings.push(finding(
            Rule::AmqpRecoveryOwner,
            path.to_string(),
            format!(
                "AMQP-RSS-RECOVERY-OWNER-01 两个显式连接 owner 必须各使用一个 ConnectionProperties factory；实际 {property_factories}"
            ),
        ));
    }
    findings
}

fn validate_amqp_connection_entry(
    facts: &[(&AmqpProductionCallable<'_>, AmqpConnectionCalls)],
    path: &str,
    entry: &str,
    context_matches: impl Fn(&str) -> bool,
) -> Vec<Finding<Rule>> {
    let owners = facts
        .iter()
        .filter(|(callable, _)| callable.is_root_free(entry))
        .collect::<Vec<_>>();
    let [owner] = owners.as_slice() else {
        return vec![finding(
            Rule::AmqpRecoveryOwner,
            path.to_string(),
            format!("AMQP-RSS-RECOVERY-OWNER-01 缺唯一 root `{entry}` entry"),
        )];
    };
    let calls = &owner.1;
    if !calls.nested_context_owner
        && matches!(calls.context_calls.as_slice(), [context] if context_matches(context))
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::AmqpRecoveryOwner,
            path.to_string(),
            format!(
                "AMQP-RSS-RECOVERY-OWNER-01 `{entry}` 必须且只能调用一次 canonical connect_with_context；实际 {:?}",
                calls.context_calls
            ),
        )]
    }
}

#[derive(Default)]
struct AmqpConnectionCalls {
    auto_recover: bool,
    sensitive_macro: bool,
    custom_properties: bool,
    nested_connection_owner: bool,
    nested_context_owner: bool,
    nested_callable_depth: usize,
    connection_properties: Vec<String>,
    property_factories: Vec<String>,
    context_calls: Vec<String>,
}

impl<'ast> Visit<'ast> for AmqpConnectionCalls {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_expr_async(&mut self, node: &'ast syn::ExprAsync) {
        self.nested_callable_depth += 1;
        syn::visit::visit_expr_async(self, node);
        self.nested_callable_depth -= 1;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nested_callable_depth += 1;
        syn::visit::visit_expr_closure(self, node);
        self.nested_callable_depth -= 1;
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if call_ends_with(&node.func, "Connection", "connect") {
            self.nested_connection_owner |= self.nested_callable_depth != 0;
            self.connection_properties.push(
                node.args
                    .iter()
                    .nth(1)
                    .map_or_else(|| "<missing>".to_string(), normalized_tokens),
            );
        }
        if call_ends_with(&node.func, "Connection", "connector") {
            self.nested_connection_owner |= self.nested_callable_depth != 0;
            self.connection_properties.push(
                node.args
                    .iter()
                    .nth(3)
                    .map_or_else(|| "<missing>".to_string(), normalized_tokens),
            );
        }
        if call_ident(&node.func).as_deref() == Some("connect_with_context") {
            self.nested_context_owner |= self.nested_callable_depth != 0;
            self.context_calls.push(
                node.args
                    .last()
                    .map_or_else(|| "<missing>".to_string(), normalized_tokens),
            );
        }
        if let syn::Expr::Path(path) = peel_expr(&node.func) {
            let mut segments = path.path.segments.iter().rev();
            let factory = segments.next().map(|segment| segment.ident.to_string());
            let owner = segments.next().map(|segment| segment.ident.to_string());
            if owner.as_deref() == Some("ConnectionProperties")
                && let Some(factory) = factory
            {
                self.property_factories.push(factory);
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.auto_recover |= node.method == "enable_auto_recover";
        if node.method == "connect"
            && normalized_tokens(&node.receiver).contains("DefaultConnectionBuilder::new()")
        {
            self.nested_connection_owner |= self.nested_callable_depth != 0;
            self.connection_properties
                .push("ConnectionProperties::default()".to_string());
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.auto_recover |= node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "enable_auto_recover");
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.custom_properties |= node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "ConnectionProperties");
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let tokens = normalized_tokens(node);
        self.sensitive_macro |= tokens.contains("enable_auto_recover")
            || tokens.contains("ConnectionProperties")
            || tokens.contains("Connection::connect");
        syn::visit::visit_macro(self, node);
    }
}

#[derive(Default)]
struct ProductionDeclarationsVisitor {
    parts: Vec<String>,
}

impl<'ast> Visit<'ast> for ProductionDeclarationsVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_test_attr(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !has_test_attr(&node.attrs) {
            self.parts.push(normalized_tokens(&node.sig));
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !has_test_attr(&node.attrs) {
            self.parts.push(normalized_tokens(&node.sig));
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if !has_test_attr(&node.attrs) {
            self.parts.push(normalized_tokens(node));
        }
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if !has_test_attr(&node.attrs) {
            self.parts.push(normalized_tokens(node));
        }
    }
}

fn production_rust_structure(content: &str) -> Option<String> {
    let file = syn::parse_file(content).ok()?;
    let mut visitor = ProductionDeclarationsVisitor::default();
    visitor.visit_file(&file);
    Some(visitor.parts.join("\n"))
}

#[derive(Default)]
struct RelayLiveFacts {
    facts: Vec<String>,
}

impl<'ast> Visit<'ast> for RelayLiveFacts {
    // A nested production helper is not a live fact of its enclosing relay owner.
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.facts.push(normalized_tokens(node));
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.facts.push(normalized_tokens(node));
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.facts.push(normalized_tokens(node));
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.facts.push(normalized_tokens(node));
        syn::visit::visit_expr_struct(self, node);
    }
}

fn relay_owner_facts(file: &syn::File, owner: Option<&str>, name: &str) -> Option<Vec<String>> {
    let mut blocks = Vec::new();
    for item in &file.items {
        match item {
            syn::Item::Fn(function)
                if owner.is_none()
                    && function.sig.ident == name
                    && !has_test_attr(&function.attrs) =>
            {
                blocks.push(function.block.as_ref());
            }
            syn::Item::Impl(item_impl)
                if owner.is_some_and(|owner| normalized_tokens(&item_impl.self_ty) == owner)
                    && !has_test_attr(&item_impl.attrs) =>
            {
                blocks.extend(item_impl.items.iter().filter_map(|item| match item {
                    syn::ImplItem::Fn(function)
                        if function.sig.ident == name && !has_test_attr(&function.attrs) =>
                    {
                        Some(&function.block)
                    }
                    _ => None,
                }));
            }
            _ => {}
        }
    }
    let [block] = blocks.as_slice() else {
        return None;
    };
    let mut facts = RelayLiveFacts::default();
    facts.visit_block(block);
    Some(facts.facts)
}

fn missing_live_seam_facts(
    file: &syn::File,
    owner: Option<&str>,
    function: &str,
    required: &[&str],
) -> Vec<String> {
    let Some(facts) = relay_owner_facts(file, owner, function) else {
        return vec!["<owner missing or ambiguous>".to_string()];
    };
    required
        .iter()
        .filter_map(|required| {
            let required = canonical_live_fact(required);
            (!facts
                .iter()
                .any(|fact| canonical_live_fact(fact).contains(&required)))
            .then_some(required)
        })
        .collect()
}

fn canonical_live_fact(fact: &str) -> String {
    fact.replace(char::is_whitespace, "").replace(",)", ")")
}

fn scan_live_seam_file(
    path: &str,
    content: &str,
    seams: &[(Option<&str>, &str, &[&str])],
) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::OutboxRelayBudget,
            path.to_string(),
            "OUTBOX-RELAY-BUDGET-01 live carrier Rust AST 无法解析".to_string(),
        )];
    };
    seams
        .iter()
        .filter_map(|(owner, function, required)| {
            let missing = missing_live_seam_facts(&file, *owner, function, required);
            (!missing.is_empty()).then_some((owner, function, missing))
        })
        .map(|(owner, function, missing)| {
            let owner = owner.map_or_else(String::new, |owner| format!("{owner}::"));
            finding(
                Rule::OutboxRelayBudget,
                path.to_string(),
                format!(
                    "OUTBOX-RELAY-BUDGET-01 live seam `{owner}{function}` 未消费 canonical typed budget/deadline: {missing:?}"
                ),
            )
        })
        .collect()
}

fn scan_relay_budget_live_seams(sources: &BTreeMap<&Path, &str>) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for (path, seams) in [
        (
            "assemblies/runtime/src/event_transport.rs",
            &[
                (
                    None,
                    "wire_event_transport",
                    &[
                        "let timing = worker.relay",
                        "pg.validate_relay_budget(timing.budget)",
                        "wire_durable(pg, DurableWiring { distributed, subscribers, execution: DurableEventExecution { per_domain, local_producers, }, timing, security, audit_key, admissions, })",
                    ][..],
                ),
                (
                    Some("RelayTiming"),
                    "from_snapshot",
                    &["RelayBudget::new(", "budget,"][..],
                ),
                (
                    None,
                    "wire_durable",
                    &[
                        "amqp::AmqpRuntimeDeps::connect_with_private_ca(&publisher, &subscriber, security.amqp_ca.clone(), &domain, timing.budget.publish_timeout())",
                    ][..],
                ),
            ][..],
        ),
        (
            "adapters/amqp/src/publisher.rs",
            &[(
                Some("AmqpPublisher"),
                "connect_with_trust",
                &[
                    "validate_publish_timeout(publish_timeout)",
                    "conn::connect_with_private_ca(endpoint, &name, true, ca)",
                    "endpoint: endpoint.clone()",
                    "PublisherTransport::new(conn, channel)",
                    "publish_timeout,",
                ][..],
            )],
        ),
        (
            "adapters/amqp/src/bundle.rs",
            &[(
                Some("AmqpRuntimeDeps"),
                "connect_with_private_ca",
                &[
                    "AmqpPublisher::connect_with_private_ca(&publisher_endpoint.0,format!(\"{name}-pub\"),publish_timeout,&ca)",
                ][..],
            )],
        ),
        (
            "adapters/postgres/src/outbox.rs",
            &[
                (
                    Some("PgOutbox"),
                    "claim_batch",
                    &[
                        "bind(self.relay_budget.lease_ttl_millis())",
                        "bind(self.relay_budget.required_budget_millis())",
                    ][..],
                ),
                (
                    Some("PgOutbox"),
                    "relay",
                    &[
                        "io_deadline_after(self.relay_budget.publisher_watchdog_timeout())",
                        "let preflight_deadline = publish_deadline - self.relay_budget.publish_timeout()",
                        "publish_preflight(&self.pool, &claimed, self.relay_budget, preflight_deadline)",
                        "self.publish_claimed_before(&claimed, publish_deadline)",
                        "settlement::published(&self.tenant_pool, &claimed, self.relay_budget)",
                    ][..],
                ),
                (
                    Some("PgOutbox"),
                    "publish_claimed_before",
                    &[
                        "with_publisher_watchdog(deadline, self.relay_budget, self.publisher.publish(request))",
                    ][..],
                ),
                (
                    None,
                    "with_publisher_watchdog",
                    &["tokio::time::timeout_at(deadline, future)"][..],
                ),
                (
                    None,
                    "publish_preflight",
                    &[
                        "let lease_ttl_millis = relay_budget.lease_ttl_millis()",
                        "let required_budget_millis = relay_budget.required_budget_millis()",
                        "deadline_global_transaction(pool, deadline,",
                        "bind(lease_ttl_millis).bind(required_budget_millis)",
                    ][..],
                ),
                (
                    Some("PgOutbox"),
                    "settle_delivery_window_expired",
                    &["settlement::same_id_expiry_dlx(", "self.relay_budget"],
                ),
                (
                    Some("PgOutbox"),
                    "settle_publish_failure",
                    &[
                        "settlement::ordinary_dlx(",
                        "settlement::retry(&self.tenant_pool, claimed, self.relay_budget)",
                        "self.relay_budget",
                    ],
                ),
            ],
        ),
        (
            "adapters/postgres/src/outbox/settlement.rs",
            &[
                (
                    None,
                    "published",
                    &[
                        "deadline_or_expired(claimed, relay_budget",
                        "execute_published(tenant_pool, claimed, relay_budget, deadline",
                    ][..],
                ),
                (
                    None,
                    "retry",
                    &[
                        "deadline_or_expired(claimed, relay_budget",
                        "execute_retry(tenant_pool, claimed, relay_budget, deadline",
                    ][..],
                ),
                (
                    None,
                    "ordinary_dlx",
                    &[
                        "let operation = SettlementOperation::Dlx",
                        "execute_dlx(tenant_pool, payload_protector",
                        "relay_budget, \"settle_dlx\"",
                        "finalize(scope, operation)",
                    ][..],
                ),
                (
                    None,
                    "same_id_expiry_dlx",
                    &[
                        "let operation = SettlementOperation::SameIdExpiryDlx",
                        "execute_dlx(tenant_pool, payload_protector",
                        "relay_budget, \"settle_delivery_window_expired\"",
                        "finalize(scope, operation)",
                    ][..],
                ),
                (
                    None,
                    "execute_published",
                    &[
                        "tenant_pool.outbox_deadline_write(infra_tenant_scope(tenant), deadline",
                        "map_outer_timeout(PHASE, relay_budget)",
                    ][..],
                ),
                (
                    None,
                    "execute_retry",
                    &[
                        "tenant_pool.outbox_deadline_write(infra_tenant_scope(tenant), deadline",
                        "map_outer_timeout(PHASE, relay_budget)",
                    ][..],
                ),
                (
                    None,
                    "execute_dlx",
                    &[
                        "deadline_or_expired(claimed, relay_budget",
                        "outbox_deadline_write(infra_tenant_scope(tenant), deadline",
                        "map_outer_timeout(phase, relay_budget)",
                    ][..],
                ),
            ],
        ),
        (
            "adapters/postgres/src/bundle.rs",
            &[
                (
                    Some("PgRuntimeHandle"),
                    "validate_relay_budget",
                    &["self.delivery_policy.validate_relay_budget(budget)"][..],
                ),
                (
                    Some("PgDomainDeps<caps::Settings>"),
                    "outbox",
                    &[
                        "PgOutbox::new(self.stores.writer_capability(), bound_domain::<caps::Settings>(), publisher, relay_budget,",
                    ][..],
                ),
                (
                    Some("PgDomainDeps<caps::Identity>"),
                    "outbox",
                    &[
                        "PgOutbox::new(self.stores.writer_capability(), bound_domain::<caps::Identity>(), publisher, relay_budget,",
                    ][..],
                ),
            ],
        ),
    ] {
        findings.extend(scan_live_seam_file(
            path,
            sources.get(Path::new(path)).copied().unwrap_or_default(),
            seams,
        ));
    }
    let runtime_path = "assemblies/runtime/src/event_transport.rs";
    if let Ok(file) = syn::parse_file(
        sources
            .get(Path::new(runtime_path))
            .copied()
            .unwrap_or_default(),
    ) && let Some(facts) = relay_owner_facts(&file, None, "wire_event_transport")
    {
        let gate = facts
            .iter()
            .position(|fact| fact.contains("pg.validate_relay_budget(timing.budget)"));
        let connect = facts.iter().position(|fact| fact.contains("wire_durable("));
        if !matches!((gate, connect), (Some(gate), Some(connect)) if gate < connect) {
            findings.push(finding(
                Rule::OutboxRelayBudget,
                runtime_path.to_string(),
                "OUTBOX-RELAY-BUDGET-01 database policy gate 必须先于 AMQP wire_durable"
                    .to_string(),
            ));
        }
    }
    findings
}

struct RelayConstructorVisitor<'a> {
    path: &'a Path,
    owner: Option<String>,
    findings: Vec<Finding<Rule>>,
}

impl RelayConstructorVisitor<'_> {
    fn inspect(&mut self, call: &syn::ExprCall) {
        let callee = normalized_tokens(call.func.as_ref());
        let owner = self.owner.as_deref().unwrap_or("<module>");
        let allowed = if callee.ends_with("amqp::AmqpRuntimeDeps::connect_with_private_ca") {
            (self.path == Path::new("assemblies/runtime/src/event_transport.rs")
                && owner == "wire_durable"
                && call.args.get(4).is_some_and(|argument| {
                    normalized_tokens(argument) == "timing.budget.publish_timeout()"
                }))
                || (self.path == Path::new("assemblies/settingsonly/src/providers.rs")
                    && owner == "build_production_infra"
                    && call.args.get(4).is_some_and(|argument| {
                        normalized_tokens(argument) == "eventing_config.publisher_confirm_timeout"
                    }))
                || (self.path == Path::new(IDENTITYAUDIT_EVENTING_TARGET)
                    && owner == "wire"
                    && call.args.get(4).is_some_and(|argument| {
                        normalized_tokens(argument) == "budget.publish_timeout()"
                    }))
        } else if callee.ends_with("amqp::AmqpRuntimeDeps::connect")
            || callee.ends_with("AmqpRuntimeDeps::connect_with_webpki_for_test")
            || callee.ends_with("AmqpPublisher::connect")
            || callee.ends_with("AmqpPublisher::connect_with_webpki_for_test")
            || callee.ends_with("AmqpSubscriber::connect")
            || callee.ends_with("AmqpSubscriber::connect_with_webpki_for_test")
        {
            false
        } else if callee.ends_with("PgOutbox::new") {
            (self.path == Path::new("adapters/postgres/src/bundle.rs")
                && matches!(
                    owner,
                    "PgDomainDeps<caps::Settings>::outbox" | "PgDomainDeps<caps::Identity>::outbox"
                ))
                || (self.path == Path::new("adapters/postgres/src/outbox.rs")
                    && owner == "fault_matrix_publish_before_settle")
        } else {
            return;
        };
        if !allowed {
            self.findings.push(finding(
                Rule::OutboxRelayBudget,
                self.path.display().to_string(),
                format!("OUTBOX-RELAY-BUDGET-01 unregistered constructor `{callee}` in `{owner}`"),
            ));
        }
    }
}

impl<'ast> Visit<'ast> for RelayConstructorVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_claim_test_only(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let previous = self.owner.replace(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.owner = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let self_ty = normalized_tokens(&node.self_ty);
        for item in &node.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            if is_claim_test_only(&function.attrs) {
                continue;
            }
            let previous = self
                .owner
                .replace(format!("{self_ty}::{}", function.sig.ident));
            syn::visit::visit_impl_item_fn(self, function);
            self.owner = previous;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.inspect(node);
        syn::visit::visit_expr_call(self, node);
    }
}

fn scan_relay_budget_constructor_callsites(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let test_only_files = external_cfg_test_module_paths(sources);
    let mut findings = Vec::new();
    for (path, content) in sources.iter().filter(|(path, _)| {
        path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && !test_only_files.contains(path)
    }) {
        let Ok(file) = syn::parse_file(content) else {
            continue;
        };
        let mut visitor = RelayConstructorVisitor {
            path,
            owner: None,
            findings: Vec::new(),
        };
        visitor.visit_file(&file);
        findings.extend(visitor.findings);
    }
    findings
}

/// 保留 migration 的 executable dollar-quoted function body，但剔除注释与普通字符串 bait。
fn relay_budget_sql_code(content: &str) -> String {
    fn strip(content: &str) -> String {
        let bytes = content.as_bytes();
        let mut output = String::with_capacity(content.len());
        let mut cursor = 0;
        while cursor < bytes.len() {
            if bytes[cursor..].starts_with(b"--") {
                cursor = skip_sql_line_comment(bytes, cursor + 2);
            } else if bytes[cursor..].starts_with(b"/*") {
                cursor = skip_sql_block_comment(bytes, cursor + 2);
            } else if matches!(bytes[cursor], b'\'' | b'"') {
                cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
                output.push(' ');
            } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
                let Some((body_start, body_end, next)) = sql_dollar_body(bytes, cursor, tag) else {
                    break;
                };
                output.push_str(&strip(&content[body_start..body_end]));
                cursor = next;
            } else {
                output.push(char::from(bytes[cursor]));
                cursor += 1;
            }
        }
        output
    }
    strip(content)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Default)]
struct RelayBudgetAuditVisitor {
    impl_owner: Option<String>,
    function: Option<String>,
    macros: Vec<(Option<String>, String, String)>,
}

impl<'ast> Visit<'ast> for RelayBudgetAuditVisitor {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        for statement in &node.stmts {
            if statement_has_test_attr(statement) {
                continue;
            }
            self.visit_stmt(statement);
            if matches!(
                statement,
                syn::Stmt::Expr(
                    syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_),
                    _
                )
            ) {
                break;
            }
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_test_attr(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !has_test_attr(&node.attrs) {
            let previous_owner = self.impl_owner.take();
            let previous = self.function.replace(node.sig.ident.to_string());
            syn::visit::visit_item_fn(self, node);
            self.function = previous;
            self.impl_owner = previous_owner;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if !has_test_attr(&node.attrs) {
            let previous = self.impl_owner.replace(
                type_path_last_ident(&node.self_ty).unwrap_or_else(|| "<unknown>".to_string()),
            );
            syn::visit::visit_item_impl(self, node);
            self.impl_owner = previous;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !has_test_attr(&node.attrs) {
            let previous = self.function.replace(node.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, node);
            self.function = previous;
        }
    }

    fn visit_expr_block(&mut self, node: &'ast syn::ExprBlock) {
        if !has_test_attr(&node.attrs) {
            syn::visit::visit_expr_block(self, node);
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if has_test_attr(&node.attrs) {
            return;
        }
        let condition = node.cond.to_token_stream().to_string();
        if condition.trim() == "false"
            || condition
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                == "cfg!(test)"
        {
            if let Some((_, alternative)) = &node.else_branch {
                self.visit_expr(alternative);
            }
            return;
        }
        syn::visit::visit_expr_if(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if matches!(name.as_deref(), Some("info" | "warn" | "error"))
            && let Some(function) = &self.function
        {
            self.macros.push((
                self.impl_owner.clone(),
                function.clone(),
                node.tokens.to_string(),
            ));
        }
        syn::visit::visit_macro(self, node);
    }
}

fn statement_has_test_attr(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Local(local) => has_test_attr(&local.attrs),
        syn::Stmt::Item(item) => match item {
            syn::Item::Const(item) => has_test_attr(&item.attrs),
            syn::Item::Enum(item) => has_test_attr(&item.attrs),
            syn::Item::ExternCrate(item) => has_test_attr(&item.attrs),
            syn::Item::Fn(item) => has_test_attr(&item.attrs),
            syn::Item::ForeignMod(item) => has_test_attr(&item.attrs),
            syn::Item::Impl(item) => has_test_attr(&item.attrs),
            syn::Item::Macro(item) => has_test_attr(&item.attrs),
            syn::Item::Mod(item) => has_test_attr(&item.attrs),
            syn::Item::Static(item) => has_test_attr(&item.attrs),
            syn::Item::Struct(item) => has_test_attr(&item.attrs),
            syn::Item::Trait(item) => has_test_attr(&item.attrs),
            syn::Item::TraitAlias(item) => has_test_attr(&item.attrs),
            syn::Item::Type(item) => has_test_attr(&item.attrs),
            syn::Item::Union(item) => has_test_attr(&item.attrs),
            syn::Item::Use(item) => has_test_attr(&item.attrs),
            _ => false,
        },
        syn::Stmt::Expr(syn::Expr::Block(block), _) => has_test_attr(&block.attrs),
        syn::Stmt::Expr(syn::Expr::If(if_), _) => has_test_attr(&if_.attrs),
        syn::Stmt::Expr(syn::Expr::Macro(macro_), _) => has_test_attr(&macro_.attrs),
        syn::Stmt::Macro(statement) => has_test_attr(&statement.attrs),
        syn::Stmt::Expr(_, _) => false,
    }
}

fn type_path_last_ident(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn scan_relay_budget_audit(
    path: &str,
    content: &str,
    marker: &str,
    expected_function: Option<&str>,
    required: &[&str],
) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return Vec::new();
    };
    let mut visitor = RelayBudgetAuditVisitor::default();
    visitor.visit_file(&file);
    let expected = expected_function.map(|expected_function| {
        expected_function
            .split_once("::")
            .map_or((None, expected_function), |(owner, function)| {
                (Some(owner), function)
            })
    });
    let matches = visitor
        .macros
        .into_iter()
        .filter(|(owner, function, tokens)| {
            expected.is_none_or(|(expected_owner, expected_function)| {
                expected_owner.is_none_or(|expected| owner.as_deref() == Some(expected))
                    && function == expected_function
            }) && tokens.contains(marker)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        let subject = expected.map_or_else(
            || format!("生产路径必须且只能有一个审计事件 `{marker}`"),
            |(expected_owner, expected_function)| {
                format!(
                    "生产函数 `{}` 必须且只能有一个审计事件 `{marker}`",
                    expected_owner.map_or_else(
                        || expected_function.to_string(),
                        |owner| format!("{owner}::{expected_function}")
                    )
                )
            },
        );
        return vec![finding(Rule::OutboxRelayBudget, path.to_string(), subject)];
    }
    let tokens = &matches[0].2;
    let compact = tokens
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut findings = required
        .iter()
        .filter(|field| !compact.contains(*field))
        .map(|field| {
            finding(
                Rule::OutboxRelayBudget,
                path.to_string(),
                format!("审计事件 `{marker}` 缺安全字段 `{field}`"),
            )
        })
        .collect::<Vec<_>>();
    for forbidden in [
        "endpoint",
        "payload",
        "metadata",
        "tenant_authority",
        "tenantAuthority",
        "vault_token",
        "Vault token",
        "error=",
        "?event_cfg",
    ] {
        if compact.contains(forbidden) {
            findings.push(finding(
                Rule::OutboxRelayBudget,
                path.to_string(),
                format!("审计事件 `{marker}` 泄漏禁止字段 `{forbidden}`"),
            ));
        }
    }
    findings
}

#[derive(Default)]
struct HardcodedRelayBudgetVisitor {
    occurrences: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for HardcodedRelayBudgetVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_test_attr(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !has_test_attr(&node.attrs) {
            syn::visit::visit_item_fn(self, node);
        }
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        let name = node.ident.to_string();
        let relay_budget_const = [
            "RELAY",
            "LEASE_TTL",
            "PUBLISH_TIMEOUT",
            "SETTLE_TIMEOUT",
            "SAFETY_MARGIN",
            "REQUIRED_BUDGET",
            "PUBLISHER_WATCHDOG",
        ]
        .iter()
        .any(|marker| name.contains(marker));
        if !has_test_attr(&node.attrs) && relay_budget_const {
            syn::visit::visit_item_const(self, node);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let rendered = normalized_tokens(node).replace('_', "");
        let forbidden = [
            "Duration::fromsecs(40)",
            "Duration::fromsecs(50)",
            "Duration::fromsecs(60)",
            "Duration::frommillis(40000)",
            "Duration::frommillis(50000)",
            "Duration::frommillis(60000)",
        ];
        if forbidden.iter().any(|needle| rendered.contains(needle)) {
            self.occurrences.push((node.span().start().line, rendered));
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn scan_hardcoded_relay_budget(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::OutboxRelayBudget,
            path.display().to_string(),
            "OUTBOX-RELAY-BUDGET-01 carrier Rust AST 无法解析".to_string(),
        )];
    };
    let mut visitor = HardcodedRelayBudgetVisitor::default();
    visitor.visit_file(&file);
    visitor
        .occurrences
        .into_iter()
        .map(|(line, rendered)| {
            finding(
                Rule::OutboxRelayBudget,
                format!("{}:{line}", path.display()),
                format!("生产 relay carrier 禁止固定 40/50/60 秒预算：`{rendered}`"),
            )
        })
        .collect()
}

#[derive(Debug)]
struct ForbiddenOccurrence {
    token: String,
    line: usize,
}

fn load_outbox_claim_cutover_sources(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut paths = workspace_member_source_files(root)?;
    let migrations = root.join("adapters/postgres/migrations");
    for entry in std::fs::read_dir(&migrations)
        .with_context(|| format!("outbox claim cutover: read dir {}", migrations.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("sql") {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let relative = rel_path(root, &path);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("outbox claim cutover: read {}", path.display()))?;
            Ok((relative, content))
        })
        .collect()
}

fn workspace_member_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest_path = root.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("outbox claim cutover: read {}", manifest_path.display()))?;
    let manifest: toml::Value = toml::from_str(&manifest)
        .with_context(|| format!("outbox claim cutover: parse {}", manifest_path.display()))?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .context("outbox claim cutover: workspace.members must be an explicit array")?;
    let mut files = BTreeSet::new();
    for member in members {
        let member = member
            .as_str()
            .context("outbox claim cutover: workspace member must be a string")?;
        let member_root = root.join(member);
        let manifest = member_root.join("Cargo.toml");
        if manifest.is_file() {
            files.insert(manifest);
        }
        let src = member_root.join("src");
        if !src.is_dir() {
            files.extend(files_with_extension_under(&member_root, "sql")?);
        } else {
            files.extend(rust_files_under(&src)?);
            files.extend(files_with_extension_under(&member_root, "sql")?);
        }
    }
    Ok(files.into_iter().collect())
}

fn scan_outbox_claim_cutover_sources(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let test_only_files = external_cfg_test_module_paths(sources);
    let relay_imports = relay_trait_imports_by_source(sources, &test_only_files);
    let mut findings = Vec::new();
    for (path, content) in sources {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("rs") if !test_only_files.contains(path) => {
                findings.extend(scan_outbox_claim_rust(
                    path,
                    content,
                    relay_imports.get(path).cloned().unwrap_or_default(),
                ))
            }
            Some("rs") => {}
            Some("sql") => findings.extend(scan_outbox_claim_sql(path, content)),
            _ => {}
        }
    }
    findings
}

fn macro_ident_words(tokens: &proc_macro2::TokenStream) -> Vec<String> {
    let mut words = Vec::new();
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Group(group) => {
                words.extend(macro_ident_words(&group.stream()));
            }
            proc_macro2::TokenTree::Ident(ident) => words.push(ident.to_string()),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
    words
}

#[derive(Default)]
struct OutboxClaimRustVisitor {
    path: PathBuf,
    relay_trait_names: BTreeMap<Vec<String>, BTreeSet<String>>,
    relay_canonical_roots: BTreeSet<String>,
    relay_crate_exports: BTreeSet<Vec<String>>,
    /// `macro_rules!` name → whether its body generates an `OutboxRelay` impl.
    local_macros: BTreeMap<Vec<String>, BTreeMap<String, bool>>,
    sqlx_query_aliases: BTreeMap<Vec<String>, BTreeSet<String>>,
    sqlx_crate_aliases: BTreeMap<Vec<String>, BTreeSet<String>>,
    module_path: Vec<String>,
    forbidden: Vec<ForbiddenOccurrence>,
    canonical_provider_count: usize,
}

impl OutboxClaimRustVisitor {
    fn new(path: &Path, imports: RelayTraitImports, file: &syn::File) -> Self {
        let forbidden = imports
            .ambiguous_glob_lines
            .iter()
            .map(|line| ForbiddenOccurrence {
                token: "consistency glob import may hide OutboxRelay impl".to_string(),
                line: *line,
            })
            .collect();
        let relay_names = imports
            .names
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            path: path.to_path_buf(),
            relay_trait_names: imports.names,
            relay_canonical_roots: imports.canonical_roots,
            relay_crate_exports: imports.crate_exports,
            local_macros: collect_local_macro_defs(file, &relay_names, &imports.module_path),
            sqlx_query_aliases: BTreeMap::new(),
            sqlx_crate_aliases: BTreeMap::new(),
            module_path: imports.module_path,
            forbidden,
            canonical_provider_count: 0,
        }
    }

    fn reject_ident(&mut self, ident: &syn::Ident) {
        self.reject_name(&ident.to_string(), ident.span().start().line);
    }

    fn reject_name(&mut self, name: &str, line: usize) {
        if (is_outbox_claim_context(&self.path)
            && matches!(name, "OutboxSource" | "PendingEntry" | "poll_pending"))
            || is_outbox_acquire_helper(&self.path, name)
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: name.to_string(),
                line,
            });
        }
    }

    fn inspect_relay_impl(&mut self, node: &syn::ItemImpl) {
        let Some((_, trait_path, _)) = &node.trait_ else {
            return;
        };
        let trait_segments = trait_path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let canonical = relay_path_is_canonical(&trait_segments, &self.relay_canonical_roots)
            || match trait_segments.as_slice() {
                [relay] => self
                    .relay_trait_names
                    .get(&self.module_path)
                    .is_some_and(|names| names.contains(relay)),
                _ => resolve_relay_symbol(&trait_segments, &self.module_path)
                    .is_some_and(|symbol| self.relay_crate_exports.contains(&symbol)),
            };
        if !canonical {
            return;
        }
        let provider = normalized_tokens(&node.self_ty);
        if self.path == Path::new(POSTGRES_OUTBOX_PATH) && provider == "PgOutbox" {
            self.canonical_provider_count += 1;
        } else {
            self.forbidden.push(ForbiddenOccurrence {
                token: format!("impl OutboxRelay for {provider}"),
                line: node.span().start().line,
            });
        }
    }

    fn reject_sqlx_query(&mut self, sql: &str, line: usize) {
        for statement in direct_sql_statements(sql) {
            if let Some((operation, retired)) = retired_sql_operation(&statement.text) {
                self.forbidden.push(ForbiddenOccurrence {
                    token: format!("sqlx {operation} retired function `{retired}`"),
                    line,
                });
            }
        }
    }

    fn is_sqlx_query_callable(&self, path: &syn::Path) -> bool {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if sqlx_query_path(path) {
            return true;
        }
        match segments.as_slice() {
            [alias]
                if self
                    .scoped_set_contains(&self.sqlx_query_aliases, alias)
                    .is_some() =>
            {
                true
            }
            [crate_alias, rest @ ..]
                if rest.last().is_some_and(|name| name.starts_with("query"))
                    && self
                        .scoped_set_contains(&self.sqlx_crate_aliases, crate_alias)
                        .is_some() =>
            {
                true
            }
            _ => false,
        }
    }

    fn scoped_set_contains<'a>(
        &self,
        table: &'a BTreeMap<Vec<String>, BTreeSet<String>>,
        name: &str,
    ) -> Option<&'a String> {
        let mut scope = self.module_path.clone();
        loop {
            if let Some(names) = table.get(&scope)
                && let Some(found) = names.get(name)
            {
                return Some(found);
            }
            if scope.is_empty() {
                return None;
            }
            scope.pop();
        }
    }

    fn lookup_local_macro(&self, name: &str) -> Option<bool> {
        let mut scope = self.module_path.clone();
        loop {
            if let Some(defs) = self.local_macros.get(&scope)
                && let Some(generates) = defs.get(name)
            {
                return Some(*generates);
            }
            if scope.is_empty() {
                return None;
            }
            scope.pop();
        }
    }

    fn module_imports_relay_trait(&self) -> bool {
        let mut scope = self.module_path.clone();
        loop {
            if self
                .relay_trait_names
                .get(&scope)
                .is_some_and(|names| !names.is_empty())
            {
                return true;
            }
            if scope.is_empty() {
                return false;
            }
            scope.pop();
        }
    }

    fn tokens_mention_relay_impl(&self, tokens: &proc_macro2::TokenStream) -> bool {
        let words = macro_ident_words(tokens);
        words.iter().enumerate().any(|(index, word)| {
            let is_relay = word == "OutboxRelay"
                || self
                    .relay_trait_names
                    .get(&self.module_path)
                    .is_some_and(|names| names.contains(word));
            is_relay
                && words.get(index + 1).is_some_and(|next| next == "for")
                && words[..index].iter().any(|prior| prior == "impl")
        })
    }

    fn inspect_relay_macro(&mut self, node: &syn::Macro) {
        if node.path.is_ident("macro_rules") {
            return;
        }
        let Some(macro_name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        let local = self.lookup_local_macro(&macro_name);
        if local == Some(true)
            || self.tokens_mention_relay_impl(&node.tokens)
            || (local.is_none()
                && macro_name.to_ascii_lowercase().contains("impl")
                && self.module_imports_relay_trait())
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: "macro-generated OutboxRelay impl".to_string(),
                line: node.span().start().line,
            });
        }
    }

    fn record_sqlx_use_bindings(&mut self, tree: &syn::UseTree) {
        let mut bindings = Vec::new();
        collect_relay_use_bindings(tree, Vec::new(), &self.module_path, 0, &mut bindings);
        for binding in bindings {
            if binding.glob {
                continue;
            }
            if binding.path.as_slice() == ["sqlx"] {
                self.sqlx_crate_aliases
                    .entry(binding.scope.clone())
                    .or_default()
                    .insert(binding.local.clone());
            }
            if binding.path.first().is_some_and(|root| root == "sqlx")
                && binding
                    .path
                    .last()
                    .is_some_and(|name| name.starts_with("query"))
                && binding.path.len() >= 2
            {
                self.sqlx_query_aliases
                    .entry(binding.scope)
                    .or_default()
                    .insert(binding.local);
            }
        }
    }
}

impl<'ast> Visit<'ast> for OutboxClaimRustVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let Some((_, items)) = &node.content else {
            return;
        };
        self.module_path.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.module_path.pop();
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_claim_test_only(&node.attrs) {
            self.record_sqlx_use_bindings(&node.tree);
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.sig.ident);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.inspect_relay_impl(node);
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.sig.ident);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_type(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        for segment in &node.segments {
            self.reject_ident(&segment.ident);
        }
        syn::visit::visit_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "poll_pending"
            && (is_outbox_claim_context(&self.path)
                || normalized_tokens(&node.receiver)
                    .to_ascii_lowercase()
                    .contains("outbox"))
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: node.method.to_string(),
                line: node.method.span().start().line,
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = peel_expr(&node.func)
            && self.is_sqlx_query_callable(&function.path)
            && let Some(sql) = node.args.iter().find_map(expr_string_literal)
        {
            self.reject_sqlx_query(&sql.value(), sql.span().start().line);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.is_sqlx_query_callable(&node.path) {
            if let Some(sql) = first_string_literal(&node.tokens) {
                self.reject_sqlx_query(&sql.value(), sql.span().start().line);
            }
        } else {
            self.inspect_relay_macro(node);
        }
        syn::visit::visit_macro(self, node);
    }
}

fn is_outbox_claim_context(path: &Path) -> bool {
    path == Path::new(EVENTEXEC_RELAY_PATH)
        || path == Path::new(POSTGRES_OUTBOX_PATH)
        || path.components().any(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("outbox")
        })
}

fn relay_path_is_canonical(path: &[String], canonical_roots: &BTreeSet<String>) -> bool {
    if !path
        .first()
        .is_some_and(|root| canonical_roots.contains(root))
    {
        return false;
    }
    match path.get(1..) {
        Some([relay]) => relay == "OutboxRelay",
        Some([module, relay]) => module == "outbox" && relay == "OutboxRelay",
        _ => false,
    }
}

fn sqlx_query_path(path: &syn::Path) -> bool {
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    segments.first().is_some_and(|root| root == "sqlx")
        && segments
            .last()
            .is_some_and(|name| name.starts_with("query"))
}

fn expr_string_literal(expr: &syn::Expr) -> Option<&syn::LitStr> {
    let syn::Expr::Lit(literal) = peel_expr(expr) else {
        return None;
    };
    let syn::Lit::Str(string) = &literal.lit else {
        return None;
    };
    Some(string)
}

fn first_string_literal(tokens: &proc_macro2::TokenStream) -> Option<syn::LitStr> {
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(string) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    return Some(string);
                }
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(string) = first_string_literal(&group.stream()) {
                    return Some(string);
                }
            }
            proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => {}
        }
    }
    None
}

#[derive(Clone, Default)]
struct RelayTraitImports {
    names: BTreeMap<Vec<String>, BTreeSet<String>>,
    canonical_roots: BTreeSet<String>,
    crate_exports: BTreeSet<Vec<String>>,
    module_path: Vec<String>,
    ambiguous_glob_lines: Vec<usize>,
}

#[derive(Clone)]
struct RelayUseBinding {
    path: Vec<String>,
    local: String,
    scope: Vec<String>,
    glob: bool,
    line: usize,
}

struct RelaySourceBindings {
    path: PathBuf,
    crate_key: String,
    module_path: Vec<String>,
    bindings: Vec<RelayUseBinding>,
    canonical_roots: BTreeSet<String>,
}

fn relay_trait_imports_by_source(
    sources: &[(PathBuf, String)],
    test_only_files: &BTreeSet<PathBuf>,
) -> BTreeMap<PathBuf, RelayTraitImports> {
    let dependency_aliases = consistency_dependency_aliases(sources);
    let files = sources
        .iter()
        .filter(|(path, _)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
                && !test_only_files.contains(path)
        })
        .filter_map(|(path, content)| {
            let file = syn::parse_file(content).ok()?;
            if is_claim_test_only(&file.attrs) {
                return None;
            }
            let module_path = source_module_path(path);
            let crate_key = source_crate_key(path);
            let mut collector = RelayUseVisitor::new(module_path.clone());
            collector.visit_file(&file);
            let mut canonical_roots = BTreeSet::from(["consistency".to_string()]);
            canonical_roots.extend(
                dependency_aliases
                    .get(&crate_key)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            canonical_roots.extend(
                collector
                    .bindings
                    .iter()
                    .filter(|binding| binding.path.as_slice() == ["consistency"])
                    .map(|binding| binding.local.clone()),
            );
            Some(RelaySourceBindings {
                path: path.clone(),
                crate_key,
                module_path,
                bindings: collector.bindings,
                canonical_roots,
            })
        })
        .collect::<Vec<_>>();

    let mut exports = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
    exports
        .entry("crates/consistency".to_string())
        .or_default()
        .insert(vec!["OutboxRelay".to_string()]);
    exports
        .entry("crates/consistency".to_string())
        .or_default()
        .insert(vec!["outbox".to_string(), "OutboxRelay".to_string()]);
    loop {
        let mut changed = false;
        for file in &files {
            for binding in &file.bindings {
                if relay_binding_is_canonical(binding, file, &exports) {
                    let mut symbol = binding.scope.clone();
                    symbol.push(binding.local.clone());
                    changed |= exports
                        .entry(file.crate_key.clone())
                        .or_default()
                        .insert(symbol);
                }
            }
        }
        if !changed {
            break;
        }
    }

    files
        .into_iter()
        .map(|file| {
            let crate_exports = exports.get(&file.crate_key).cloned().unwrap_or_default();
            let mut imports = RelayTraitImports {
                canonical_roots: file.canonical_roots.clone(),
                crate_exports,
                module_path: file.module_path.clone(),
                ..RelayTraitImports::default()
            };
            for binding in &file.bindings {
                if relay_binding_is_canonical(binding, &file, &exports) {
                    imports
                        .names
                        .entry(binding.scope.clone())
                        .or_default()
                        .insert(binding.local.clone());
                }
                if binding.glob && relay_glob_targets_canonical(binding, &file, &exports) {
                    imports.ambiguous_glob_lines.push(binding.line);
                }
            }
            (file.path, imports)
        })
        .collect()
}

fn relay_binding_is_canonical(
    binding: &RelayUseBinding,
    file: &RelaySourceBindings,
    exports: &BTreeMap<String, BTreeSet<Vec<String>>>,
) -> bool {
    relay_path_is_canonical(&binding.path, &file.canonical_roots)
        || resolve_relay_symbol(&binding.path, &binding.scope).is_some_and(|symbol| {
            exports
                .get(&file.crate_key)
                .is_some_and(|symbols| symbols.contains(&symbol))
        })
}

fn consistency_dependency_aliases(
    sources: &[(PathBuf, String)],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
    for (path, content) in sources
        .iter()
        .filter(|(path, _)| path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml"))
    {
        let Ok(manifest) = toml::from_str::<toml::Value>(content) else {
            continue;
        };
        let Some(root) = manifest.as_table() else {
            continue;
        };
        let crate_key = path
            .parent()
            .map(|parent| parent.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        collect_consistency_aliases(root, aliases.entry(crate_key).or_default());
    }
    aliases
}

fn collect_consistency_aliases(table: &toml::value::Table, aliases: &mut BTreeSet<String>) {
    for (key, value) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            let Some(dependencies) = value.as_table() else {
                continue;
            };
            for (alias, dependency) in dependencies {
                let canonical = alias == "consistency"
                    || dependency
                        .as_table()
                        .and_then(|entry| entry.get("package"))
                        .and_then(toml::Value::as_str)
                        == Some("consistency");
                if canonical {
                    aliases.insert(alias.replace('-', "_"));
                }
            }
        } else if let Some(nested) = value.as_table() {
            collect_consistency_aliases(nested, aliases);
        }
    }
}

fn relay_glob_targets_canonical(
    binding: &RelayUseBinding,
    file: &RelaySourceBindings,
    exports: &BTreeMap<String, BTreeSet<Vec<String>>>,
) -> bool {
    if binding
        .path
        .first()
        .is_some_and(|root| file.canonical_roots.contains(root))
    {
        return true;
    }
    let Some(module) = resolve_relay_symbol(&binding.path, &binding.scope) else {
        return false;
    };
    exports.get(&file.crate_key).is_some_and(|symbols| {
        symbols
            .iter()
            .any(|symbol| symbol.len() == module.len() + 1 && symbol.starts_with(module.as_slice()))
    })
}

fn resolve_relay_symbol(path: &[String], scope: &[String]) -> Option<Vec<String>> {
    let (mut symbol, cursor) = match path.first().map(String::as_str) {
        Some("crate") => (Vec::new(), 1),
        Some("self") => (scope.to_vec(), 1),
        Some("super") => {
            let mut symbol = scope.to_vec();
            let mut cursor = 0;
            while path.get(cursor).is_some_and(|segment| segment == "super") {
                symbol.pop()?;
                cursor += 1;
            }
            (symbol, cursor)
        }
        Some(_) => (scope.to_vec(), 0),
        None => return None,
    };
    symbol.extend(path[cursor..].iter().cloned());
    Some(symbol)
}

struct RelayUseVisitor {
    bindings: Vec<RelayUseBinding>,
    scope: Vec<String>,
}

impl RelayUseVisitor {
    fn new(scope: Vec<String>) -> Self {
        Self {
            bindings: Vec::new(),
            scope,
        }
    }
}

impl<'ast> Visit<'ast> for RelayUseVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let Some((_, items)) = &node.content else {
            return;
        };
        self.scope.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.scope.pop();
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_claim_test_only(&node.attrs) {
            collect_relay_use_bindings(
                &node.tree,
                Vec::new(),
                &self.scope,
                node.span().start().line,
                &mut self.bindings,
            );
        }
    }
}

fn collect_relay_use_bindings(
    tree: &syn::UseTree,
    mut prefix: Vec<String>,
    scope: &[String],
    line: usize,
    bindings: &mut Vec<RelayUseBinding>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_relay_use_bindings(&path.tree, prefix, scope, line, bindings);
        }
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            bindings.push(RelayUseBinding {
                path: prefix,
                local: name.ident.to_string(),
                scope: scope.to_vec(),
                glob: false,
                line,
            });
        }
        syn::UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            bindings.push(RelayUseBinding {
                path: prefix,
                local: rename.rename.to_string(),
                scope: scope.to_vec(),
                glob: false,
                line,
            });
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_relay_use_bindings(item, prefix.clone(), scope, line, bindings);
            }
        }
        syn::UseTree::Glob(_) => {
            bindings.push(RelayUseBinding {
                path: prefix,
                local: String::new(),
                scope: scope.to_vec(),
                glob: true,
                line,
            });
        }
    }
}

fn source_crate_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .take_while(|part| *part != "src")
        .collect::<Vec<_>>()
        .join("/")
}

fn source_module_path(path: &Path) -> Vec<String> {
    let mut segments = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .skip_while(|part| part != "src")
        .skip(1)
        .collect::<Vec<_>>();
    let Some(file) = segments.pop() else {
        return Vec::new();
    };
    match file.as_str() {
        "lib.rs" | "main.rs" | "mod.rs" => segments,
        _ => {
            segments.push(file.strip_suffix(".rs").unwrap_or(&file).to_string());
            segments
        }
    }
}

fn is_claim_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| cfg_meta_implies_test(&meta)))
    })
}

fn cfg_meta_implies_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::NameValue(value) if value.path.is_ident("feature") => {
            matches!(
                &value.value,
                syn::Expr::Lit(literal)
                    if matches!(
                        &literal.lit,
                        syn::Lit::Str(feature)
                            if matches!(
                                feature.value().as_str(),
                                "integration-test-support" | "fault-matrix-test-support"
                            )
                    )
            )
        }
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(children) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                children.iter().any(cfg_meta_implies_test)
            } else {
                !children.is_empty() && children.iter().all(cfg_meta_implies_test)
            }
        }
        syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
    }
}

fn external_cfg_test_module_paths(sources: &[(PathBuf, String)]) -> BTreeSet<PathBuf> {
    let available = sources
        .iter()
        .filter(|(path, _)| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut intrinsic_test_only = BTreeSet::new();
    let mut test_only_refs = BTreeSet::new();
    let mut production_refs = BTreeSet::new();
    for (path, content) in sources {
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(file) = syn::parse_file(content) else {
            continue;
        };
        let file_test_only = is_claim_test_only(&file.attrs);
        if file_test_only || crate::src_scan::is_crate_internal_integration_test_source(path) {
            intrinsic_test_only.insert(path.clone());
        }
        let base = rust_module_base(path);
        collect_external_module_reachability(
            &file.items,
            &base,
            file_test_only,
            &available,
            &mut test_only_refs,
            &mut production_refs,
        );
    }
    let mut excluded = intrinsic_test_only;
    excluded.extend(test_only_refs.difference(&production_refs).cloned());
    excluded
}

fn rust_module_base(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    match path.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

fn collect_external_module_reachability(
    items: &[syn::Item],
    base: &Path,
    inherited_test_only: bool,
    available: &BTreeSet<PathBuf>,
    test_only_refs: &mut BTreeSet<PathBuf>,
    production_refs: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let test_only = inherited_test_only || is_claim_test_only(&module.attrs);
        if let Some((_, nested)) = &module.content {
            collect_external_module_reachability(
                nested,
                &base.join(module.ident.to_string()),
                test_only,
                available,
                test_only_refs,
                production_refs,
            );
            continue;
        }
        for candidate in [
            base.join(format!("{}.rs", module.ident)),
            base.join(module.ident.to_string()).join("mod.rs"),
        ] {
            if available.contains(&candidate) {
                if test_only {
                    test_only_refs.insert(candidate);
                } else {
                    production_refs.insert(candidate);
                }
            }
        }
    }
}

fn is_outbox_acquire_helper(path: &Path, ident: &str) -> bool {
    let explicit_outbox_helper =
        ident.contains("outbox") && ident.contains("acquire") && ident.contains("lease");
    let contextual_helper = ident == "acquire_lease"
        && (path == Path::new(EVENTEXEC_RELAY_PATH)
            || path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().contains("outbox")));
    explicit_outbox_helper || contextual_helper
}

fn collect_local_macro_defs(
    file: &syn::File,
    relay_names: &BTreeSet<String>,
    module_path: &[String],
) -> BTreeMap<Vec<String>, BTreeMap<String, bool>> {
    struct Collector<'a> {
        scope: Vec<String>,
        relay_names: &'a BTreeSet<String>,
        defs: BTreeMap<Vec<String>, BTreeMap<String, bool>>,
    }

    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if is_claim_test_only(&node.attrs) {
                return;
            }
            let Some((_, items)) = &node.content else {
                return;
            };
            self.scope.push(node.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.scope.pop();
        }

        fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
            if is_claim_test_only(&node.attrs) || !node.mac.path.is_ident("macro_rules") {
                return;
            }
            let Some(name) = &node.ident else {
                return;
            };
            let words = macro_ident_words(&node.mac.tokens);
            let generates = words.iter().enumerate().any(|(index, word)| {
                (word == "OutboxRelay" || self.relay_names.contains(word))
                    && words.get(index + 1).is_some_and(|next| next == "for")
                    && words[..index].iter().any(|prior| prior == "impl")
            });
            self.defs
                .entry(self.scope.clone())
                .or_default()
                .insert(name.to_string(), generates);
        }
    }

    let mut collector = Collector {
        scope: module_path.to_vec(),
        relay_names,
        defs: BTreeMap::new(),
    };
    collector.visit_file(file);
    collector.defs
}

fn scan_outbox_claim_rust(
    path: &Path,
    content: &str,
    imports: RelayTraitImports,
) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "outbox claimed-entry carrier Rust AST 无法解析".to_string(),
        )];
    };
    let mut visitor = OutboxClaimRustVisitor::new(path, imports, &file);
    visitor.visit_file(&file);
    visitor.forbidden.sort_by_key(|occurrence| occurrence.line);
    let mut findings = visitor
        .forbidden
        .into_iter()
        .map(|occurrence| {
            finding(
                Rule::OutboxClaimCutover,
                format!("{}:{}", path.display(), occurrence.line),
                format!(
                    "claimed-entry cutover 禁止生产 legacy/rogue 路径: `{}`",
                    occurrence.token
                ),
            )
        })
        .collect::<Vec<_>>();
    if path == Path::new(POSTGRES_OUTBOX_PATH) && visitor.canonical_provider_count != 1 {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "canonical provider 必须恰有一个 `impl OutboxRelay for PgOutbox`".to_string(),
        ));
    }
    if path == Path::new(EVENTEXEC_RELAY_PATH) && !eventexec_claim_flow_is_connected(&file) {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "eventexec 必须保持 claim_batch → Vec<A::Claim> → relay(claim)".to_string(),
        ));
    }
    if path == Path::new(TARGET) && !runtime_relay_worker_is_connected(&file) {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "runtime wire_domain_relay 必须将 canonical PgOutbox 交给已注册 WorkerSpec 的 spawn_relay"
                .to_string(),
        ));
    }
    findings
}

#[derive(Clone)]
struct RelayBatchContract {
    store_index: usize,
    claim_index: usize,
}

fn eventexec_claim_flow_is_connected(file: &syn::File) -> bool {
    let Some(domain) = unique_top_level_fn(file, "relay_domain_once") else {
        return false;
    };
    let Some(batch) = unique_top_level_fn(file, "relay_batch") else {
        return false;
    };
    let Some(contract) = relay_batch_contract(batch) else {
        return false;
    };
    relay_domain_calls_batch_with_claim(domain, &contract)
}

fn unique_top_level_fn<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function)
            if function.sig.ident == name && !has_test_attr(&function.attrs) =>
        {
            Some(function)
        }
        _ => None,
    });
    let function = functions.next()?;
    functions.next().is_none().then_some(function)
}

fn relay_batch_contract(function: &syn::ItemFn) -> Option<RelayBatchContract> {
    let parameters = function_parameters(&function.sig);
    let claim_parameters = parameters
        .iter()
        .filter(|(_, _, ty)| {
            let rendered = normalized_tokens(*ty);
            rendered.starts_with("Vec<") && rendered.contains("::Claim>")
        })
        .collect::<Vec<_>>();
    let [claim_parameter] = claim_parameters.as_slice() else {
        return None;
    };
    let claim_index = claim_parameter.0;
    let claim_name = claim_parameter.1.as_str();
    let matching = function
        .block
        .stmts
        .iter()
        .filter_map(statement_expr)
        .filter_map(|expr| awaited_call(expr, "join_all"))
        .filter_map(|call| call.args.first().and_then(relay_map_contract))
        .filter(|(claims, _)| claims == claim_name)
        .collect::<Vec<_>>();
    let [(_, store)] = matching.as_slice() else {
        return None;
    };
    let store_index = parameters
        .iter()
        .find_map(|(index, name, _)| (name == store).then_some(*index))?;
    Some(RelayBatchContract {
        store_index,
        claim_index,
    })
}

fn function_parameters(signature: &syn::Signature) -> Vec<(usize, String, &syn::Type)> {
    signature
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| match input {
            syn::FnArg::Typed(typed) => {
                pat_ident(&typed.pat).map(|name| (index, name, typed.ty.as_ref()))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn pat_ident(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(typed) => pat_ident(&typed.pat),
        _ => None,
    }
}

fn relay_map_contract(expr: &syn::Expr) -> Option<(String, String)> {
    let syn::Expr::MethodCall(map) = peel_expr(expr) else {
        return None;
    };
    if map.method != "map" || map.args.len() != 1 {
        return None;
    }
    let syn::Expr::MethodCall(iter) = peel_expr(&map.receiver) else {
        return None;
    };
    if iter.method != "into_iter" || !iter.args.is_empty() {
        return None;
    }
    let claims = simple_expr_ident(&iter.receiver)?;
    let syn::Expr::Closure(closure) = peel_expr(map.args.first()?) else {
        return None;
    };
    if closure.inputs.len() != 1 {
        return None;
    }
    let input = closure.inputs.first()?;
    let claim = pat_ident(input)?;
    let syn::Expr::Async(future) = peel_expr(&closure.body) else {
        return None;
    };
    let relay_stores = block_tail_expr(&future.block)
        .into_iter()
        .flat_map(|tail| relay_tail_stores(tail, &claim))
        .collect::<BTreeSet<_>>();
    if relay_stores.len() != 1 {
        return None;
    }
    Some((claims, relay_stores.into_iter().next()?))
}

fn relay_domain_calls_batch_with_claim(
    function: &syn::ItemFn,
    contract: &RelayBatchContract,
) -> bool {
    let parameters = function_parameters(&function.sig)
        .into_iter()
        .map(|(_, name, _)| name)
        .collect::<BTreeSet<_>>();
    let mut derived = BTreeSet::new();
    let mut claim_store = None;
    for statement in &function.block.stmts {
        let Some(expr) = statement_expr(statement) else {
            continue;
        };
        if awaited_call(expr, "relay_batch").is_some_and(|call| {
            let arguments = call.args.iter().cloned().collect::<Vec<_>>();
            call_argument_ident(&arguments, contract.claim_index)
                .is_some_and(|claim| derived.contains(&claim))
                && call_argument_ident(&arguments, contract.store_index) == claim_store
        }) {
            return true;
        }
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let Some(binding) = pat_ident(&local.pat) else {
            continue;
        };
        if let Some(store) = claim_batch_receiver(expr) {
            if parameters.contains(&store) {
                derived.insert(binding);
                claim_store = Some(store);
            }
        } else if expr_derives_from(expr, &derived) {
            derived.insert(binding);
        }
    }
    false
}

fn statement_expr(statement: &syn::Stmt) -> Option<&syn::Expr> {
    match statement {
        syn::Stmt::Local(local) => local.init.as_ref().map(|init| init.expr.as_ref()),
        syn::Stmt::Expr(expr, _) => Some(expr),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
    }
}

fn call_argument_ident(arguments: &[syn::Expr], index: usize) -> Option<String> {
    arguments.get(index).and_then(simple_expr_ident)
}

fn simple_expr_ident(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    (path.path.segments.len() == 1).then(|| path.path.segments[0].ident.to_string())
}

fn claim_batch_receiver(expr: &syn::Expr) -> Option<String> {
    awaited_method(expr, "claim_batch").and_then(|call| simple_expr_ident(&call.receiver))
}

fn expr_derives_from(expr: &syn::Expr, names: &BTreeSet<String>) -> bool {
    match peel_expr(expr) {
        syn::Expr::Path(_) => simple_expr_ident(expr).is_some_and(|name| names.contains(&name)),
        syn::Expr::Match(expr) => expr_derives_from(&expr.expr, names),
        _ => false,
    }
}

fn peel_non_await(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        expr = match expr {
            syn::Expr::Paren(paren) => &paren.expr,
            syn::Expr::Group(group) => &group.expr,
            syn::Expr::Reference(reference) => &reference.expr,
            syn::Expr::Try(try_expr) => &try_expr.expr,
            _ => return expr,
        };
    }
}

fn awaited_call<'a>(expr: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Await(awaited) = peel_non_await(expr) else {
        return None;
    };
    let syn::Expr::Call(call) = peel_expr(&awaited.base) else {
        return None;
    };
    (call_ident(&call.func).as_deref() == Some(name)).then_some(call)
}

fn awaited_method<'a>(expr: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprMethodCall> {
    let syn::Expr::Await(awaited) = peel_non_await(expr) else {
        return None;
    };
    let syn::Expr::MethodCall(call) = peel_expr(&awaited.base) else {
        return None;
    };
    (call.method == name).then_some(call)
}

fn block_tail_expr(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.last()? {
        syn::Stmt::Expr(expr, None) => Some(expr),
        _ => None,
    }
}

fn relay_tail_stores(expr: &syn::Expr, claim: &str) -> Vec<String> {
    match peel_non_await(expr) {
        syn::Expr::Await(_) => awaited_method(expr, "relay")
            .filter(|call| {
                call.args.len() == 1
                    && call.args.first().and_then(simple_expr_ident).as_deref() == Some(claim)
            })
            .and_then(|call| simple_expr_ident(&call.receiver))
            .into_iter()
            .collect(),
        syn::Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .flat_map(|element| relay_tail_stores(element, claim))
            .collect(),
        _ => Vec::new(),
    }
}

fn runtime_relay_worker_is_connected(file: &syn::File) -> bool {
    let Some(function) = unique_top_level_fn(file, "wire_domain_relay") else {
        return false;
    };
    let parameters = function_parameters(&function.sig);
    let outboxes = parameters
        .iter()
        .filter(|(_, _, ty)| normalized_tokens(*ty) == "postgres::PgOutbox")
        .collect::<Vec<_>>();
    let modules = parameters
        .iter()
        .filter(|(_, _, ty)| normalized_tokens(*ty) == "&mutDomainModuleResult")
        .collect::<Vec<_>>();
    let ([outbox], [module]) = (outboxes.as_slice(), modules.as_slice()) else {
        return false;
    };
    let workers = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| worker_binding(statement, outbox.1.as_str()))
        .collect::<BTreeSet<_>>();
    if workers.len() != 1 {
        return false;
    }
    function.block.stmts.iter().any(|statement| {
        let Some(expr) = statement_expr(statement) else {
            return false;
        };
        let syn::Expr::MethodCall(push) = peel_expr(expr) else {
            return false;
        };
        push.method == "push_worker"
            && push.args.len() == 1
            && push
                .args
                .first()
                .and_then(simple_expr_ident)
                .is_some_and(|worker| workers.contains(&worker))
            && simple_expr_ident(&push.receiver).as_deref() == Some(module.1.as_str())
    })
}

fn worker_binding(statement: &syn::Stmt, outbox: &str) -> Option<String> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let worker = match &local.pat {
        syn::Pat::Ident(ident) => ident.ident.to_string(),
        syn::Pat::Type(typed) if normalized_tokens(&typed.ty) == "WorkerSpec" => {
            pat_ident(&typed.pat)?
        }
        _ => return None,
    };
    let init = local.init.as_ref()?.expr.as_ref();
    let syn::Expr::Call(policy) = peel_expr(init) else {
        return None;
    };
    if !call_ends_with(&policy.func, "WorkerSpec", "relay_deferred") || policy.args.len() != 3 {
        return None;
    }
    let syn::Expr::Closure(closure) = peel_expr(policy.args.iter().nth(2)?) else {
        return None;
    };
    let tail = closure_tail_expr(&closure.body)?;
    let syn::Expr::Call(resource) = peel_expr(tail) else {
        return None;
    };
    if !call_ends_with(&resource.func, "DynManagedResource", "new_box") || resource.args.len() != 1
    {
        return None;
    }
    let syn::Expr::Call(spawn) = peel_expr(resource.args.first()?) else {
        return None;
    };
    (call_ident(&spawn.func).as_deref() == Some("spawn_relay")
        && spawn
            .args
            .iter()
            .any(|argument| simple_expr_ident(argument).as_deref() == Some(outbox)))
    .then_some(worker)
}

fn closure_tail_expr(body: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Block(block) = peel_expr(body) else {
        return Some(peel_expr(body));
    };
    match block.block.stmts.last()? {
        syn::Stmt::Expr(expr, None) => Some(expr),
        _ => None,
    }
}

fn scan_outbox_claim_sql(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    if LEGACY_OUTBOX_MIGRATIONS
        .iter()
        .any(|allowed| path == Path::new(allowed))
    {
        return Vec::new();
    }
    let direct = direct_sql_statements(content);
    let mut statements = direct.clone();
    statements.extend(dynamic_execute_literals(content));
    statements.sort_by_key(|statement| statement.line);
    let mut findings = statements
        .into_iter()
        .filter_map(|statement| {
            if statement.text.is_empty() {
                Some(finding(
                    Rule::OutboxClaimCutover,
                    format!("{}:{}", path.display(), statement.line),
                    "atomic claim cutover 后禁止无法静态解析的 dynamic EXECUTE".to_string(),
                ))
            } else {
                retired_sql_operation(&statement.text).map(|(operation, retired)| {
                    finding(
                        Rule::OutboxClaimCutover,
                        format!("{}:{}", path.display(), statement.line),
                        format!(
                            "atomic claim cutover 后禁止 {operation} retired function `{retired}`"
                        ),
                    )
                })
            }
        })
        .collect::<Vec<_>>();
    if path == Path::new(ATOMIC_OUTBOX_CLAIM_MIGRATION) {
        findings.extend(missing_0057_retirement_witnesses(path, &direct));
    }
    findings
}

#[derive(Clone)]
struct LocatedSqlStatement {
    text: String,
    line: usize,
}

fn direct_sql_statements(content: &str) -> Vec<LocatedSqlStatement> {
    let code = sql_code_without_comments_and_literals(content).to_ascii_uppercase();
    let mut line = 1;
    code.split_inclusive(';')
        .filter_map(|statement| {
            let statement_line = line
                + statement
                    .chars()
                    .take_while(|character| character.is_whitespace())
                    .filter(|character| *character == '\n')
                    .count();
            line += statement.bytes().filter(|byte| *byte == b'\n').count();
            (!statement.trim().is_empty()).then(|| LocatedSqlStatement {
                text: statement.to_string(),
                line: statement_line,
            })
        })
        .collect()
}

fn missing_0057_retirement_witnesses(
    path: &Path,
    statements: &[LocatedSqlStatement],
) -> Vec<Finding<Rule>> {
    const REQUIRED: &[(&str, &str)] = &[
        (
            "DROPFUNCTIONIFEXISTSRSS_OUTBOX_POLL_PENDING(TEXT,BIGINT)",
            "rss_outbox_poll_pending(text, bigint)",
        ),
        (
            "DROPFUNCTIONIFEXISTSRSS_OUTBOX_ACQUIRE_LEASE(TEXT)",
            "rss_outbox_acquire_lease(text)",
        ),
    ];
    let drops = statements
        .iter()
        .map(|statement| {
            statement
                .text
                .chars()
                .filter(|character| !character.is_whitespace() && *character != ';')
                .collect::<String>()
        })
        .collect::<BTreeSet<_>>();
    REQUIRED
        .iter()
        .filter(|(signature, _)| !drops.contains(*signature))
        .map(|(_, display)| {
            finding(
                Rule::OutboxClaimCutover,
                format!("{}:1", path.display()),
                format!("0057 必须显式 DROP retired function `{display}`"),
            )
        })
        .collect()
}

fn retired_sql_operation(statement: &str) -> Option<(&'static str, &'static str)> {
    let statement = statement.trim_start().to_ascii_uppercase();
    let operation = statement.split_whitespace().next()?;
    if operation == "DROP" {
        return None;
    }
    let retired = RETIRED_OUTBOX_FUNCTIONS
        .iter()
        .copied()
        .find(|function| statement.contains(function))?;
    match operation {
        "CREATE" => Some(("CREATE", retired)),
        "ALTER" => Some(("ALTER", retired)),
        "GRANT" => Some(("GRANT", retired)),
        _ => Some(("调用", retired)),
    }
}

fn sql_code_without_comments_and_literals(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut output = String::with_capacity(content.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            output.push(' ');
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes[cursor..].starts_with(b"/*") {
            output.push(' ');
            cursor += 2;
            while cursor < bytes.len() && !bytes[cursor..].starts_with(b"*/") {
                preserve_sql_newline(&mut output, bytes[cursor]);
                cursor += 1;
            }
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == b'\'' {
            output.push(' ');
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\'' {
                    if bytes.get(cursor + 1) == Some(&b'\'') {
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    preserve_sql_newline(&mut output, bytes[cursor]);
                    cursor += 1;
                }
            }
        } else if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'"' {
                    if bytes.get(cursor + 1) == Some(&b'"') {
                        output.push('"');
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    output.push(char::from(bytes[cursor]));
                    cursor += 1;
                }
            }
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            output.push(' ');
            cursor += tag.len();
            let remaining = &bytes[cursor..];
            let skipped = remaining
                .windows(tag.len())
                .position(|window| window == tag)
                .map_or(remaining.len(), |offset| offset + tag.len());
            output.extend(
                remaining[..skipped]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .map(|_| '\n'),
            );
            cursor += skipped;
        } else {
            output.push(char::from(bytes[cursor]));
            cursor += 1;
        }
    }
    output
}

fn preserve_sql_newline(output: &mut String, byte: u8) {
    if byte == b'\n' {
        output.push('\n');
    }
}

fn dynamic_execute_literals(content: &str) -> Vec<LocatedSqlStatement> {
    let bytes = content.as_bytes();
    let mut statements = Vec::new();
    let mut cursor = 0;
    let mut statement_start = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            let Some((body_start, body_end, next)) = sql_dollar_body(bytes, cursor, tag) else {
                break;
            };
            if is_executable_sql_body_prefix(&content[statement_start..cursor]) {
                statements.extend(dynamic_execute_literals_in_body(
                    &content[body_start..body_end],
                    sql_line_at(content, body_start),
                ));
            }
            cursor = next;
        } else if bytes[cursor] == b';' {
            cursor += 1;
            statement_start = cursor;
        } else {
            cursor += 1;
        }
    }
    statements
}

fn dynamic_execute_literals_in_body(
    body: &str,
    body_start_line: usize,
) -> Vec<LocatedSqlStatement> {
    let bytes = body.as_bytes();
    let mut statements = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if sql_word_at(bytes, cursor, b"EXECUTE") {
            let start = cursor + b"EXECUTE".len();
            let end = sql_expression_end(bytes, start);
            let literals = sql_string_literals(&body[start..end]);
            let expression = body[start..end].trim_start();
            let is_sql_grammar_execute = ["ON", "FUNCTION", "PROCEDURE"].into_iter().any(|word| {
                expression.len() >= word.len()
                    && sql_word_at(expression.as_bytes(), 0, word.as_bytes())
            });
            if !is_sql_grammar_execute {
                statements.push(LocatedSqlStatement {
                    text: literals,
                    line: body_start_line
                        + body[..cursor].bytes().filter(|byte| *byte == b'\n').count(),
                });
            }
            cursor = end.saturating_add(1);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            cursor = skip_sql_dollar(bytes, cursor, tag);
        } else {
            cursor += 1;
        }
    }
    statements
}

fn sql_line_at(content: &str, offset: usize) -> usize {
    1 + content.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

fn is_executable_sql_body_prefix(prefix: &str) -> bool {
    let code = sql_code_without_comments_and_literals(prefix).to_ascii_uppercase();
    let words = code
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.first() == Some(&"DO")
        || (words.contains(&"CREATE")
            && (words.contains(&"FUNCTION") || words.contains(&"PROCEDURE"))
            && words.last() == Some(&"AS"))
}

fn sql_dollar_body(bytes: &[u8], cursor: usize, tag: &[u8]) -> Option<(usize, usize, usize)> {
    let body_start = cursor + tag.len();
    let remaining = &bytes[body_start..];
    let body_len = remaining
        .windows(tag.len())
        .position(|window| window == tag)?;
    let body_end = body_start + body_len;
    Some((body_start, body_end, body_end + tag.len()))
}

fn skip_sql_line_comment(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        cursor += 1;
    }
    cursor
}

fn skip_sql_block_comment(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && !bytes[cursor..].starts_with(b"*/") {
        cursor += 1;
    }
    (cursor + 2).min(bytes.len())
}

fn skip_sql_quote(bytes: &[u8], mut cursor: usize, quote: u8) -> usize {
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == quote {
            if bytes.get(cursor + 1) == Some(&quote) {
                cursor += 2;
            } else {
                return cursor + 1;
            }
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn sql_word_at(bytes: &[u8], cursor: usize, word: &[u8]) -> bool {
    let Some(candidate) = bytes.get(cursor..cursor + word.len()) else {
        return false;
    };
    candidate.eq_ignore_ascii_case(word)
        && cursor
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        && bytes
            .get(cursor + word.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn sql_expression_end(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            cursor = skip_sql_dollar(bytes, cursor, tag);
        } else if bytes[cursor] == b';' {
            return cursor;
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn sql_string_literals(expression: &str) -> String {
    let bytes = expression.as_bytes();
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            output.push(' ');
            let body_start = cursor + tag.len();
            let remaining = &bytes[body_start..];
            let body_len = remaining
                .windows(tag.len())
                .position(|window| window == tag)
                .unwrap_or(remaining.len());
            output.push_str(&String::from_utf8_lossy(&remaining[..body_len]));
            cursor = (body_start + body_len + tag.len()).min(bytes.len());
        } else if bytes[cursor] != b'\'' {
            cursor += 1;
        } else {
            output.push(' ');
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\'' {
                    if bytes.get(cursor + 1) == Some(&b'\'') {
                        output.push('\'');
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    output.push(char::from(bytes[cursor]));
                    cursor += 1;
                }
            }
        }
    }
    output
}

fn sql_dollar_tag(bytes: &[u8], start: usize) -> Option<&[u8]> {
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let end = bytes[start + 1..].iter().position(|byte| *byte == b'$')? + start + 1;
    bytes[start + 1..end]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .then_some(&bytes[start..=end])
}

fn skip_sql_dollar(bytes: &[u8], cursor: usize, tag: &[u8]) -> usize {
    let body_start = cursor + tag.len();
    let remaining = &bytes[body_start..];
    body_start
        + remaining
            .windows(tag.len())
            .position(|window| window == tag)
            .map_or(remaining.len(), |offset| offset + tag.len())
}

fn rel_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_consumer_policy_raw_effect_is_rejected(case: &str, sources: &[(PathBuf, &str)]) {
        let sources = sources
            .iter()
            .map(|(path, source)| (path.clone(), (*source).to_string()))
            .collect::<Vec<_>>();
        let (_, findings) = scan_consumer_policy_sources(&sources);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ConsumerExternalEffectCapability
                    && finding.detail.contains("unauthorized external effect")
            }),
            "synthetic-red `{case}` must expose an unauthorized raw external effect: {findings:#?}"
        );
    }

    #[test]
    fn consumer_policy_guard_accepts_closed_capability_without_raw_effect() {
        let sources = [(
            PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
            r#"
            fn audit_consumer_tx_handler() -> ConsumerTxHandler<TransactionalOnly> {
                ConsumerTxHandler::transactional(|tx| async move {
                    tx.write_business_row().await?;
                    tx.append_outbox().await?;
                    tx.mark_inbox_done().await
                })
            }
            "#
            .to_string(),
        )];
        let (roots, findings) = scan_consumer_policy_sources(&sources);
        assert_eq!(roots, 1);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn consumer_policy_guard_roots_concrete_settings_reconciler() {
        assert_consumer_policy_raw_effect_is_rejected(
            "settings-owner-reconcile",
            &[(
                PathBuf::from("crates/settings/src/application.rs"),
                r#"
                impl ConfigVersionReconciler {
                    fn reconcile(&self, publisher: DynPublisher) {
                        publisher.publish(message);
                    }
                }
                "#,
            )],
        );
    }

    #[test]
    fn consumer_policy_guard_rejects_direct_raw_publisher_call() {
        assert_consumer_policy_raw_effect_is_rejected(
            "direct",
            &[(
                PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
                r#"
                fn audit_consumer_tx_handler(publisher: DynPublisher) {
                    publisher.publish(message);
                }
                "#,
            )],
        );
    }

    #[test]
    fn consumer_policy_guard_rejects_aliased_raw_publisher_call() {
        assert_consumer_policy_raw_effect_is_rejected(
            "alias",
            &[(
                PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
                r#"
                use eventbus::Publisher as EffectSink;
                fn audit_consumer_tx_handler(sink: EffectSink) {
                    EffectSink::publish(&sink, message);
                }
                "#,
            )],
        );
    }

    #[test]
    fn consumer_policy_guard_rejects_cross_file_helper_raw_call() {
        assert_consumer_policy_raw_effect_is_rejected(
            "cross-file",
            &[
                (
                    PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
                    r#"
                    fn audit_consumer_tx_handler(effect: &EffectHelper) {
                        effect.emit(message);
                    }
                    "#,
                ),
                (
                    PathBuf::from("adapters/postgres/src/effect_helper.rs"),
                    r#"
                    impl EffectHelper {
                        fn emit(&self, message: Message) {
                            self.publisher.publish(message);
                        }
                    }
                    "#,
                ),
            ],
        );
    }

    #[test]
    fn consumer_policy_guard_rejects_macro_hidden_raw_call() {
        assert_consumer_policy_raw_effect_is_rejected(
            "macro",
            &[(
                PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
                r#"
                macro_rules! emit_external {
                    ($publisher:expr, $message:expr) => {
                        $publisher.publish($message)
                    };
                }
                fn audit_consumer_tx_handler(publisher: DynPublisher) {
                    emit_external!(publisher, message);
                }
                "#,
            )],
        );
    }

    #[test]
    fn consumer_policy_guard_rejects_raw_effect_bypass_matrix() {
        let cases = [
            (
                "function-item-alias",
                r#"
                fn audit_consumer_tx_handler(publisher: DynPublisher) {
                    let send = DynPublisher::publish;
                    send(&publisher, message);
                }
                "#,
            ),
            (
                "renamed-wrapper",
                r#"
                fn deliver_raw(publisher: DynPublisher) {
                    publisher.publish(message);
                }
                fn audit_consumer_tx_handler(publisher: DynPublisher) {
                    use crate::deliver_raw as renamed_wrapper;
                    renamed_wrapper(publisher);
                }
                "#,
            ),
            (
                "ufcs",
                r#"
                fn audit_consumer_tx_handler(publisher: DynPublisher) {
                    DynPublisher::publish(&publisher, message);
                }
                "#,
            ),
            (
                "chained-http-send",
                r#"
                fn audit_consumer_tx_handler(client: HttpClient) {
                    client.post(url).send();
                }
                "#,
            ),
            (
                "http-request",
                r#"
                fn audit_consumer_tx_handler(client: HttpClient) {
                    client.request(request);
                }
                "#,
            ),
            (
                "http-execute",
                r#"
                fn audit_consumer_tx_handler(client: HttpClient) {
                    client.execute(request);
                }
                "#,
            ),
            (
                "email-send",
                r#"
                fn audit_consumer_tx_handler(email: EmailClient) {
                    email.send(message);
                }
                "#,
            ),
            (
                "object-store-put",
                r#"
                fn audit_consumer_tx_handler(store: DynObjectStore) {
                    store.put_object(key, bytes);
                }
                "#,
            ),
            (
                "cloud-upload",
                r#"
                fn audit_consumer_tx_handler(cloud: CloudClient) {
                    cloud.upload(key, bytes);
                }
                "#,
            ),
            (
                "helper-object-store",
                r#"
                fn persist_blob(store: DynObjectStore) {
                    store.put_object(key, bytes);
                }
                fn audit_consumer_tx_handler(store: DynObjectStore) {
                    persist_blob(store);
                }
                "#,
            ),
            (
                "macro-hidden-http",
                r#"
                macro_rules! call_external {
                    ($client:expr) => {
                        $client.post(url).send()
                    };
                }
                fn audit_consumer_tx_handler(client: HttpClient) {
                    call_external!(client);
                }
                "#,
            ),
            (
                "macro-hidden-email",
                r#"
                macro_rules! send_mail {
                    ($email:expr) => {
                        $email.send(message)
                    };
                }
                fn audit_consumer_tx_handler(email: EmailClient) {
                    send_mail!(email);
                }
                "#,
            ),
        ];
        for (case, source) in cases {
            assert_consumer_policy_raw_effect_is_rejected(
                case,
                &[(
                    PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
                    source,
                )],
            );
        }
    }

    #[test]
    fn consumer_policy_guard_fails_closed_when_helper_resolution_is_ambiguous() {
        let mut source = String::from(
            r#"
            fn audit_consumer_tx_handler() {
                shared_helper();
            }
            "#,
        );
        for index in 0..5 {
            source.push_str(&format!(
                "mod candidate_{index} {{ fn shared_helper() {{}} }}\n"
            ));
        }
        let (_, findings) = scan_consumer_policy_sources(&[(
            PathBuf::from("adapters/postgres/src/consumer_tx.rs"),
            source,
        )]);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ConsumerExternalEffectCapability
                    && finding.detail.contains("ambiguous helper resolution")
            }),
            "more than four same-name helper candidates must fail closed: {findings:#?}"
        );
    }

    #[allow(clippy::unwrap_used)]
    fn scan_producer_source(content: &str) -> (ProducerFacts, Vec<Finding<Rule>>) {
        let file = syn::parse_file(content).unwrap();
        let imports = SpecImports::from_file(&file);
        let mut facts = ProducerFacts::default();
        let mut findings = Vec::new();
        let mut visitor = ProducerVisitor::new(
            &imports,
            Path::new("crates/identity/src/application.rs"),
            &mut facts,
            &mut findings,
        );
        visitor.visit_file(&file);
        (facts, findings)
    }

    /// Raw entry/envelope construction and handwritten helpers must never satisfy the production
    /// event witness after the generated emit cutover.
    #[test]
    fn producer_ast_rejects_raw_authoring_as_event_evidence() {
        for source in [
            r#"
            use generated::event::identity_v1::session_created::SPEC as SESSION_SPEC;
            fn produce() {
                let entry = EventEntry::new(EventTopic::parse(SESSION_SPEC.topic())?, id, payload);
                let envelope = OutboxEnvelopeParts::new(
                    SESSION_SPEC.contract(), tenant, subject, actor
                );
            }
            "#,
            r#"
            use generated::event::identity_v1::session_created::*;
            fn build_entry(spec: EventSpec) {
                EventEntry::new(EventTopic::parse(spec.topic())?, id, payload)
            }
            fn produce() {
                let entry = build_entry(SPEC);
                let envelope = OutboxEnvelopeParts::new(
                    SPEC.contract(), tenant, subject, actor
                );
            }
            "#,
        ] {
            let (facts, findings) = scan_producer_source(source);
            assert!(
                findings.is_empty(),
                "raw syntax is ignored, not reclassified: {findings:?}"
            );
            assert!(
                facts.emits.is_empty(),
                "raw authoring must not count as emit evidence"
            );
        }

        let event = ActiveEvent {
            contract_id: "identity.session-created".to_string(),
            spec_path: "generated::event::identity_v1::session_created::SPEC".to_string(),
        };
        assert_eq!(
            validate_event_facts(&event, &ProducerFacts::default()).len(),
            1
        );
    }

    #[test]
    fn producer_ast_accepts_sealed_generated_emit_wrapper() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::identity_v1::session_created::{
                self, IdentitySessionCreatedPayload,
            };
            fn produce() {
                let payload = IdentitySessionCreatedPayload {
                    session_id,
                    subject,
                    tenant_id,
                    occurred_at,
                };
                let event = session_created::emit(
                    &encoder, &payload, tenant, subject, actor, id
                ).await?;
            }
            "#,
        );
        let spec = "generated::event::identity_v1::session_created::SPEC";
        assert!(findings.is_empty(), "{findings:?}");
        assert!(facts.emits.contains(spec));
    }

    #[test]
    fn producer_ast_accepts_exact_generated_emit_alias() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::identity_v1::session_created::emit as emit_session_created;
            fn produce() {
                emit_session_created(&encoder, &payload, tenant, subject, actor, id).await?;
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert!(
            facts
                .emits
                .contains("generated::event::identity_v1::session_created::SPEC")
        );
    }

    #[test]
    fn producer_ast_rejects_multiple_generated_emit_specs_in_one_site() {
        let (facts, findings) = scan_producer_source(
            r#"
            fn produce() {
                generated::event::identity_v1::session_created::emit(
                    &encoder, &session_payload, tenant, subject, actor, id
                ).await?;
                generated::event::settings_v1::emit(
                    &encoder, &settings_payload, tenant, subject, actor, id
                ).await?;
            }
            "#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(facts.emits.is_empty());
    }

    #[test]
    fn producer_ast_rejects_literals_and_ignores_comment_string_spoofs() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::settings_v1::SPEC;
            const NOTE: &str = "EventEntry::new(EventTopic::parse(SPEC.topic()), id, payload)";
            // OutboxEnvelopeParts::new(SPEC.contract(), tenant, subject, actor);
            fn produce() {
                let entry = EventEntry::new(EventTopic::parse("settings.changed")?, id, payload);
                let envelope = OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor);
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert!(facts.emits.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn framework_event_spec_path_comes_from_contract_path_not_owner() {
        assert_eq!(
            event_spec_path(Path::new("_seed/v1/contract.toml"), "v1", None).unwrap(),
            "generated::event::_seed_v1::SPEC"
        );
        assert_eq!(
            event_spec_path(
                Path::new("identity/v1/role-revoked/contract.toml"),
                "v1",
                Some("role_revoked")
            )
            .unwrap(),
            "generated::event::identity_v1::role_revoked::SPEC"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn workspace_event_transport_and_active_producers_pass_guard() {
        let (_summary, findings) = EventTransportGuard.check().unwrap();
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn scan_content_rejects_redis_consumer_claimer_needles() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            "let _: RedisInboxStore; let _ = \"RSS_REDIS_CLAIM_TTL_MS\";",
        );
        assert!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::RedisConsumerClaimer)
                .count()
                == 2
        );
    }

    #[test]
    fn runtime_consumer_tx_compatibility_carrier_is_fail_closed() {
        assert!(runtime_consumer_tx_compat_findings("pub mod event_transport;", false).is_empty());
        for (runtime_lib, compatibility_file_exists) in [
            ("mod consumer_tx; pub mod event_transport;", false),
            ("pub mod event_transport;", true),
        ] {
            let findings =
                runtime_consumer_tx_compat_findings(runtime_lib, compatibility_file_exists);
            assert!(findings.iter().any(|finding| {
                finding.rule == Rule::MissingBundleFragment
                    && finding.detail.contains("compatibility carrier")
            }));
        }
    }

    #[test]
    fn scan_content_rejects_runtime_redis_inbox_direct_wire() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            fn wire_consumer_resource_bundle(redis: RedisRuntimeDeps) {
                let group = subscription.group().clone();
                let inbox = redis.infra().inbox(ttl);
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RedisConsumerClaimer)
        );
    }

    #[test]
    fn scan_content_rejects_runtime_redis_inbox_split_wire() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            fn wire_consumer_resource_bundle(redis: RedisRuntimeDeps) {
                let group = subscription.group().clone();
                let infra = redis.infra();
                let inbox = infra.inbox(ttl);
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RedisConsumerClaimer)
        );
    }

    #[test]
    fn scan_content_accepts_pg_inbox_bundle() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            pub fn bridge_generated_subscriptions(bindings: Vec<SubscriberBinding>) {
                eventing_composition::bridge_generated_subscriptions(bindings)
            }
            struct EventTransportWiring<'a> {
                pg: &'a Pg,
                distributed: Distributed,
                subscribers: BridgedSubscriptions,
                cfg: Config,
                worker: Worker,
                audit_key: Key,
                admissions: Admissions,
            }
            fn wire_event_transport(wiring: EventTransportWiring<'_>) {
                let EventTransportWiring {
                    pg,
                    distributed,
                    subscribers,
                    cfg,
                    worker,
                    audit_key,
                    admissions,
                } = wiring;
            }
            fn wire_consumer_resource_bundle(pg: Pg, module: &mut Module) {
                let group = subscription.group().clone();
                let inbox = pg.infra().inbox();
                let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
                let dlx = DynDeadLetterStore::new_box(
                    pg.infra()
                        .dead_letter(security.dlx_payload_protector.clone()),
                );
                let worker =
                    consumer_tx_worker_for_subscription(pg, &subscription, audit_key, inputs)?;
                let consumer_probe = probe();
                match subscription.readiness() {
                    SubscriberReadiness::Required => {
                        module.push_worker(worker);
                        module.push_probe(consumer_probe);
                    }
                }
                wire_inbox_sweeper(pg, timing, write_admission, module)?;
            }
            fn consumer_tx_worker_for_subscription(token: Token, pg: Pg, audit_key: Key, inputs: Inputs) {
                match token.dispatch() {
                    SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
                    | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
                    | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
                    | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
                    | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit =>
                        AuditConsumerFactory::new(
                            pg,
                            audit_key.context("audit key required")?,
                        ).worker(token, inputs),
                    SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings =>
                        SettingsConsumerFactory::new(pg).worker(token, inputs),
                }
            }
            "#,
        );
        let unrelated = findings
            .iter()
            .filter(|finding| {
                finding.detail.contains("BridgedSubscription")
                    || finding.detail.contains("bridge_generated_subscriptions")
                    || finding.detail.contains("wire_event_transport")
                    || finding.detail.contains("consumer bundle")
            })
            .collect::<Vec<_>>();
        assert!(unrelated.is_empty(), "{unrelated:?}");
    }

    #[test]
    fn scan_content_rejects_consumer_tx_plan_without_external_effect_policy() {
        let canonical = include_str!("../../composition/eventing/src/lib.rs");
        let red = canonical.replace("    policy: ExternalEffectPolicy,\n", "");
        assert_ne!(red, canonical);
        let findings = scan_composition_content(Path::new(EVENTING_COMPOSITION_TARGET), &red);
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::MissingBundleFragment
                && finding.detail.contains("externalEffectPolicy")
        }));
    }

    #[test]
    fn workspace_composition_closes_consumer_tx_external_effect_policy() {
        let findings = scan_composition_content(
            Path::new(EVENTING_COMPOSITION_TARGET),
            include_str!("../../composition/eventing/src/lib.rs"),
        );
        assert!(
            !findings.iter().any(|finding| {
                finding.rule == Rule::MissingBundleFragment
                    && finding.detail.contains("externalEffectPolicy")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn workspace_eventing_composition_shape_is_closed() {
        let findings = scan_composition_content(
            Path::new(EVENTING_COMPOSITION_TARGET),
            include_str!("../../composition/eventing/src/lib.rs"),
        );
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn dedicated_runtime_funnel_rejects_production_builder() {
        let sources = [(
            PathBuf::from("assemblies/runtime/src/event_transport.rs"),
            r#"
            fn production_worker() {
                let runtime = tokio::runtime::Builder::new_current_thread().build();
            }
            #[cfg(test)]
            mod tests {
                fn harness() {
                    let runtime = tokio::runtime::Builder::new_current_thread().build();
                }
            }
            "#
            .to_string(),
        )];
        let findings = scan_dedicated_runtime_sources(&sources);
        assert_eq!(findings.len(), 1, "test-only builder must be ignored");
        assert_eq!(findings[0].rule, Rule::DedicatedRuntimeFunnel);
    }

    #[test]
    fn workspace_dedicated_runtime_funnel_is_closed() {
        let sources = DEDICATED_RUNTIME_ASSEMBLY_TARGETS
            .iter()
            .map(|target| {
                let content = match *target {
                    TARGET => include_str!("../../assemblies/runtime/src/event_transport.rs"),
                    IDENTITYAUDIT_EVENTING_TARGET => {
                        include_str!("../../assemblies/identityaudit/src/eventing.rs")
                    }
                    "assemblies/settingsonly/src/eventing.rs" => {
                        include_str!("../../assemblies/settingsonly/src/eventing.rs")
                    }
                    "assemblies/settingsonly/src/dlx.rs" => {
                        include_str!("../../assemblies/settingsonly/src/dlx.rs")
                    }
                    _ => unreachable!("closed dedicated runtime target list"),
                };
                (PathBuf::from(target), content.to_string())
            })
            .collect::<Vec<_>>();
        let findings = scan_dedicated_runtime_sources(&sources);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn subscribe_supervise_rejects_one_shot_worker_exiting() {
        let sources = [(
            PathBuf::from("crates/eventexec/src/consumer_worker.rs"),
            r#"
            pub fn spawn_consumer_ackable_subscriber() {
                match subscriber.subscribe_ackable(topic, token).await {
                    Ok(stream) => {}
                    Err(err) => {
                        tracing::error!("consumer: subscribe_ackable failed; worker exiting");
                        return Err(err);
                    }
                }
            }
            "#
            .to_string(),
        )];
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ConsumerSubscribeSupervise),
            "{findings:#?}"
        );
    }

    #[test]
    fn subscribe_supervise_rejects_definition_bait_without_spawn_call() {
        // 文件含 `run_ackable_subscription_loop` 函数定义标识符诱饵，但 spawn 仍是 one-shot
        // 且无 `worker exiting`——旧 contains 守卫会空转放行；AST 必须拒绝。
        let sources = [(
            PathBuf::from("crates/eventexec/src/consumer_worker.rs"),
            r#"
            pub async fn run_ackable_subscription_loop() {}
            pub fn spawn_consumer_ackable_subscriber() {
                match subscriber.subscribe_ackable(topic, token).await {
                    Ok(_stream) => {}
                    Err(err) => {
                        return Err(err);
                    }
                }
            }
            pub fn spawn_consumer_ackable_tx_subscriber() {
                run_ackable_subscription_loop();
            }
            "#
            .to_string(),
        )];
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ConsumerSubscribeSupervise
                    && f.detail.contains("spawn_consumer_ackable_subscriber")),
            "{findings:#?}"
        );
    }

    #[test]
    fn subscribe_supervise_rejects_missing_required_spawn() {
        // 仅定义其中一个 required spawn → 另一缺席必须报 Finding（防 continue 空转）。
        let sources = [(
            PathBuf::from("crates/eventexec/src/consumer_worker.rs"),
            r#"
            pub fn spawn_consumer_ackable_subscriber() {
                run_ackable_subscription_loop();
            }
            "#
            .to_string(),
        )];
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsumerSubscribeSupervise
                    && f.detail.contains("spawn_consumer_ackable_tx_subscriber")
                    && f.detail.contains("未在任何 SUBSCRIBE_SUPERVISE_TARGETS")
            }),
            "{findings:#?}"
        );
    }

    #[test]
    fn subscribe_supervise_rejects_renamed_spawn() {
        // 改名后 required 标识符消失 → presence 门必须红。
        let sources = [(
            PathBuf::from("crates/eventexec/src/consumer_worker.rs"),
            r#"
            pub fn spawn_consumer_ackable_subscriber_renamed() {
                run_ackable_subscription_loop();
            }
            pub fn spawn_consumer_ackable_tx_subscriber_renamed() {
                run_ackable_subscription_loop();
            }
            "#
            .to_string(),
        )];
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsumerSubscribeSupervise
                    && f.detail.contains("spawn_consumer_ackable_subscriber")
                    && f.detail.contains("未在任何 SUBSCRIBE_SUPERVISE_TARGETS")
            }),
            "{findings:#?}"
        );
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsumerSubscribeSupervise
                    && f.detail.contains("spawn_consumer_ackable_tx_subscriber")
                    && f.detail.contains("未在任何 SUBSCRIBE_SUPERVISE_TARGETS")
            }),
            "{findings:#?}"
        );
    }

    #[test]
    fn subscribe_supervise_ignores_forbidden_phrase_in_doc_attrs() {
        // rustdoc 含禁串不得误红；主门仍靠 spawn 函数体 AST 调用。
        let sources = [(
            PathBuf::from("crates/eventexec/src/consumer_worker.rs"),
            r#"
            /// consumer: subscribe_ackable failed; worker exiting
            pub fn spawn_consumer_ackable_subscriber() {
                run_ackable_subscription_loop();
            }
            /// worker exiting
            pub fn spawn_consumer_ackable_tx_subscriber() {
                run_ackable_subscription_loop();
            }
            "#
            .to_string(),
        )];
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(
            findings.is_empty(),
            "doc attr forbidden phrase must not trip guard: {findings:#?}"
        );
    }

    #[test]
    fn strip_cfg_test_modules_drops_top_level_test_mod() {
        let stripped = strip_cfg_test_modules(
            "fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn bait() { run_ackable_subscription_loop(); }\n}\n",
        );
        assert!(stripped.contains("fn prod"));
        assert!(!stripped.contains("bait"));
        assert!(!stripped.contains("run_ackable_subscription_loop"));
    }

    #[test]
    fn strip_cfg_test_modules_drops_nested_test_mod() {
        let stripped = strip_cfg_test_modules(
            "mod outer {\n    fn prod() {}\n    #[cfg(test)]\n    mod tests {\n        fn bait() {}\n    }\n}\n",
        );
        assert!(stripped.contains("fn prod"));
        assert!(!stripped.contains("bait"));
    }

    #[test]
    fn external_test_modules_exclude_the_integration_test_subtree() {
        let sources = [
            (
                PathBuf::from("adapters/postgres/src/integration_tests.rs"),
                "mod outbox_tests;\n".to_string(),
            ),
            (
                PathBuf::from(POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH),
                "fn fixture_only() {}\n".to_string(),
            ),
            (
                PathBuf::from("adapters/postgres/src/integration_tests/support/helpers.rs"),
                "fn support_only() {}\n".to_string(),
            ),
            (
                PathBuf::from("adapters/postgres/src/outbox.rs"),
                "pub fn production() {}\n".to_string(),
            ),
        ];
        let excluded = external_cfg_test_module_paths(&sources);
        assert!(excluded.contains(Path::new(POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH)));
        assert!(excluded.contains(Path::new(
            "adapters/postgres/src/integration_tests/support/helpers.rs"
        )));
        assert!(!excluded.contains(Path::new("adapters/postgres/src/outbox.rs")));
    }

    #[test]
    fn producer_test_file_excludes_integration_tests_support_without_tests_suffix() {
        assert!(is_producer_test_file(Path::new(
            "adapters/postgres/src/integration_tests/support/helpers.rs"
        )));
        assert!(is_producer_test_file(Path::new(
            "adapters/postgres/src/integration_tests.rs"
        )));
        assert!(!is_producer_test_file(Path::new(
            "adapters/postgres/src/outbox.rs"
        )));
        assert!(!is_producer_test_file(Path::new(
            "adapters/postgres/src/support/helpers.rs"
        )));
    }

    #[test]
    fn workspace_subscribe_supervise_is_closed() {
        let sources = SUBSCRIBE_SUPERVISE_TARGETS
            .iter()
            .map(|target| {
                let content = match *target {
                    "crates/eventexec/src/consumer_worker.rs" => {
                        include_str!("../../crates/eventexec/src/consumer_worker.rs")
                    }
                    "composition/eventing/src/consumer_tx.rs" => {
                        include_str!("../../composition/eventing/src/consumer_tx.rs")
                    }
                    _ => unreachable!("closed subscribe supervise target list"),
                };
                (PathBuf::from(target), content.to_string())
            })
            .collect::<Vec<_>>();
        let findings = scan_subscribe_supervise_sources(&sources);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn eventing_composition_guard_rejects_shared_source_drift() {
        let canonical = include_str!("../../composition/eventing/src/lib.rs");
        for (needle, replacement) in [
            (
                "bridge_subscriptions_with_events_selected(bindings, generated::event::EVENTS, admitted_dispatch)",
                "bridge_subscriptions_with_events_selected(bindings, &[], admitted_dispatch)",
            ),
            (
                "        admitted_audit_dispatch,\n",
                "        admitted_dispatch,\n",
            ),
            ("cfg!(feature = \"audit-consumers\")", "true"),
            (
                ".policy_updated_consumer_tx(",
                ".role_assigned_consumer_tx(",
            ),
        ] {
            let red = canonical.replace(needle, replacement);
            assert_ne!(red, canonical, "missing fixture needle: {needle}");
            let findings = scan_composition_content(Path::new(EVENTING_COMPOSITION_TARGET), &red);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingBundleFragment),
                "mutation `{needle}` must fail closed: {findings:#?}"
            );
        }
    }

    #[test]
    fn eventing_composition_guard_rejects_audit_handler_permutation() {
        let canonical = include_str!("../../composition/eventing/src/lib.rs");
        let red = canonical
            .replace(".role_assigned_consumer_tx(", ".permuted_role_consumer_tx(")
            .replace(".role_revoked_consumer_tx(", ".role_assigned_consumer_tx(")
            .replace(".permuted_role_consumer_tx(", ".role_revoked_consumer_tx(");
        assert_ne!(red, canonical, "permutation fixture must mutate source");
        let findings = scan_composition_content(Path::new(EVENTING_COMPOSITION_TARGET), &red);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::MissingBundleFragment
                    && finding.detail.contains("Postgres handler")
            }),
            "role-assigned / role-revoked permutation must fail closed: {findings:#?}"
        );
    }

    #[test]
    fn identityaudit_durable_closure_guard_has_green_and_red_witnesses() {
        let canonical = include_str!("../../assemblies/identityaudit/src/eventing.rs");
        let path = Path::new(IDENTITYAUDIT_EVENTING_TARGET);
        assert!(
            identityaudit_closure_findings(path, canonical).is_empty(),
            "canonical identityaudit closure must remain admitted"
        );

        for (needle, replacement) in [
            (
                "validate_audit_closure(subscriptions.subscriptions())?;",
                "let _ = &subscriptions;",
            ),
            (
                "eventing_composition::AuditConsumerFactory::new",
                "eventing_composition::SettingsConsumerFactory::new",
            ),
        ] {
            let red = canonical.replace(needle, replacement);
            assert_ne!(red, canonical, "missing fixture needle: {needle}");
            assert!(
                identityaudit_closure_findings(path, &red)
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingBundleFragment),
                "mutation `{needle}` must fail closed"
            );
        }
    }

    #[test]
    fn canonical_inbox_sampler_inventory_has_green_and_red_witnesses() {
        for (path, canonical, worker, expected) in [
            (
                TARGET,
                include_str!("../../assemblies/runtime/src/event_transport.rs"),
                "\"inbox-backlog-sampler\"",
                1,
            ),
            (
                IDENTITYAUDIT_EVENTING_TARGET,
                include_str!("../../assemblies/identityaudit/src/eventing.rs"),
                "\"identityaudit-inbox-backlog-sampler\"",
                0,
            ),
            (
                "assemblies/settingsonly/src/eventing.rs",
                include_str!("../../assemblies/settingsonly/src/eventing.rs"),
                "\"settingsonly-inbox-backlog-sampler\"",
                0,
            ),
        ] {
            assert!(inbox_sampler_inventory_content_findings(path, canonical).is_empty());
            let red = if expected == 1 {
                let red = canonical.replace(worker, "\"removed-inbox-sampler\"");
                assert_ne!(red, canonical);
                red
            } else {
                format!(
                    "{canonical}\nfn forbidden_reference_sampler() {{ let _ = {worker}; coordinated_inbox_backlog_sampler_loop(); ProbeName::parse(INBOX_SAMPLER_PROBE); }}"
                )
            };
            assert!(
                inbox_sampler_inventory_content_findings(path, &red)
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingBundleFragment)
            );
            let duplicate_worker =
                format!("{canonical}\nconst DUPLICATE_INBOX_WORKER: &str = {worker};");
            assert!(!inbox_sampler_inventory_content_findings(path, &duplicate_worker).is_empty());
            let duplicate_probe = format!(
                "{canonical}\nfn duplicate_inbox_probe() {{ let _ = ProbeName::parse(INBOX_SAMPLER_PROBE); }}"
            );
            assert!(!inbox_sampler_inventory_content_findings(path, &duplicate_probe).is_empty());
            let bait = format!(
                "{canonical}\n#[cfg(test)] mod inventory_bait {{ fn bait() {{ coordinated_inbox_backlog_sampler_loop(); ProbeName::parse(INBOX_SAMPLER_PROBE); let _ = {worker}; }} }}\n// {worker}"
            );
            assert!(inbox_sampler_inventory_content_findings(path, &bait).is_empty());
        }
    }

    #[test]
    fn identityaudit_bypass_and_relay_budget_exceptions_are_fail_closed() {
        let canonical = include_str!("../../assemblies/identityaudit/src/eventing.rs");
        let path = Path::new(IDENTITYAUDIT_EVENTING_TARGET);
        assert!(scan_bypass_content(path, canonical).is_empty());

        let bypass_red = canonical.replace(
            "eventing_composition::AuditConsumerFactory::new",
            "eventing_composition::SettingsConsumerFactory::new",
        );
        assert!(
            scan_bypass_content(path, &bypass_red)
                .iter()
                .any(|finding| {
                    finding.rule == Rule::ProductionConsumerBundleBypass
                        && finding.detail.contains("pg.infra().inbox(")
                })
        );

        let green = vec![(
            PathBuf::from(IDENTITYAUDIT_EVENTING_TARGET),
            "fn wire() { amqp::AmqpRuntimeDeps::connect_with_private_ca(&publisher, &subscriber, ca, name, budget.publish_timeout()); }".to_string(),
        )];
        assert!(scan_relay_budget_constructor_callsites(&green).is_empty());
        for red in [
            "fn wire() { amqp::AmqpRuntimeDeps::connect(url, name, budget.publish_timeout()); }",
            "fn wire() { amqp::AmqpRuntimeDeps::connect_with_private_ca(&publisher, &subscriber, ca, name, Duration::from_secs(40)); }",
        ] {
            assert!(
                scan_relay_budget_constructor_callsites(&[(
                    PathBuf::from(IDENTITYAUDIT_EVENTING_TARGET),
                    red.to_string(),
                )])
                .iter()
                .any(|finding| finding.rule == Rule::OutboxRelayBudget)
            );
        }
    }

    #[test]
    fn test_only_transport_constructors_require_a_closed_test_cfg() {
        let path = PathBuf::from("crates/rogue/src/lib.rs");
        let call = "amqp::AmqpRuntimeDeps::connect_with_webpki_for_test(url, name, timeout);";
        for source in [
            format!("fn production() {{ {call} }}"),
            format!("#[cfg(feature = \"backend\")] fn disguised() {{ {call} }}"),
            format!("#[cfg(any(test, feature = \"backend\"))] fn disguised() {{ {call} }}"),
        ] {
            assert!(
                scan_relay_budget_constructor_callsites(&[(path.clone(), source)])
                    .iter()
                    .any(|finding| finding.rule == Rule::OutboxRelayBudget)
            );
        }
        for source in [
            format!("#[cfg(test)] fn test_only() {{ {call} }}"),
            format!("#[cfg(feature = \"integration-test-support\")] fn test_only() {{ {call} }}"),
        ] {
            assert!(scan_relay_budget_constructor_callsites(&[(path.clone(), source)]).is_empty());
        }
    }

    #[test]
    fn scan_content_rejects_symbol_only_consumer_tx_plan_resolver() {
        let findings = scan_composition_content(
            Path::new(EVENTING_COMPOSITION_TARGET),
            r#"
            pub struct BridgedSubscription {
                event: EventSpec,
                subscription: SubscriptionSpec,
                group: ConsumerGroup,
                consumer_tx: ConsumerTxPlan,
            }
            pub fn bridge_generated_subscriptions(bindings: Vec<SubscriberBinding>) {
                bridge_subscriptions_with_events(bindings, generated::event::EVENTS)
            }
            fn resolve_parts() {
                if false {
                    SubscriberExecution::AdapterNative;
                    SubscriberExecution::DomainEffect;
                    ConsumerTxPlan::AuditSessionCreated;
                    ConsumerTxPlan::AuditRoleAssigned;
                    ConsumerTxPlan::AuditRoleRevoked;
                    ConsumerTxPlan::AuditPolicyUpdated;
                    ConsumerTxPlan::SettingsConfigVersionChanged;
                }
            }
            "#,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::MissingBundleFragment && finding.detail.contains("resolver")
        }));
    }

    #[allow(clippy::expect_used)]
    fn workspace_consumer_tx_plan_resolver() -> syn::ItemFn {
        syn::parse_file(include_str!("../../composition/eventing/src/lib.rs"))
            .expect("eventing composition parses")
            .items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "resolve_parts" => Some(item),
                _ => None,
            })
            .expect("composition resolver exists")
    }

    fn resolver_dispatch_match_mut(resolver: &mut syn::ItemFn) -> Option<&mut syn::ExprMatch> {
        resolver.block.stmts.iter_mut().find_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let initializer = local.init.as_mut()?;
            let syn::Expr::Match(mapping) = initializer.expr.as_mut() else {
                return None;
            };
            (normalized_tokens(&mapping.expr) == "dispatch").then_some(mapping)
        })
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn consumer_tx_plan_resolver_rejects_fail_open_wildcard() {
        let mut resolver = workspace_consumer_tx_plan_resolver();
        let Some(mapping) = resolver_dispatch_match_mut(&mut resolver) else {
            panic!("resolver must end in match");
        };
        mapping.arms.last_mut().expect("dispatch arm").pat = syn::parse_quote!(_);
        assert!(!consumer_tx_plan_resolver_is_closed(&resolver));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn consumer_tx_plan_resolver_accepts_new_typed_dispatch_without_shadow_registry() {
        let mut resolver = workspace_consumer_tx_plan_resolver();
        let Some(mapping) = resolver_dispatch_match_mut(&mut resolver) else {
            panic!("resolver must end in match");
        };
        let mut arm = mapping.arms.last().expect("dispatch arm").clone();
        arm.pat = syn::parse_quote!(SubscriptionDispatchKey::FutureEventV1Audit);
        mapping.arms.push(arm);
        assert!(consumer_tx_plan_resolver_is_closed(&resolver));
    }

    #[test]
    fn scan_content_rejects_missing_pg_bundle_fragment() {
        let findings =
            scan_runtime_content(Path::new(TARGET), "fn wire_consumer_resource_bundle()");
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingBundleFragment)
        );
    }

    #[test]
    fn scan_domain_content_rejects_consumer_bundle_bypass() {
        let findings = scan_domain_content(
            Path::new("crates/identity/src/lib.rs"),
            "let _ = PgInboxStore; spawn_consumer_ackable_subscriber();",
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn fault_matrix_harness_skip_requires_exact_path_and_feature_gate() {
        let gated_lib = r#"
#[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
"#;
        assert!(is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            gated_lib
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new("adapters/postgres/src/nested/fault_matrix.rs"),
            gated_lib
        ));
    }

    #[test]
    fn fault_matrix_harness_skip_rejects_missing_or_wrong_gate() {
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            "pub mod fault_matrix;"
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            r#"
#[cfg(test)]
pub mod fault_matrix;
"#
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            r#"
// #[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
"#
        ));
    }

    #[test]
    fn scan_bypass_content_rejects_production_spawn_outside_bridge() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            "spawn_consumer(); spawn_consumer_ackable_subscriber();",
        );
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ProductionConsumerBundleBypass)
        );
    }

    #[test]
    fn scan_bypass_content_rejects_tx_spawn_direct_and_qualified() {
        for content in [
            "fn wire() { spawn_consumer_ackable_tx_subscriber(); }",
            "fn wire() { eventexec::spawn_consumer_ackable_tx_subscriber(); }",
        ] {
            let findings =
                scan_bypass_content(Path::new("assemblies/runtime/src/other.rs"), content);
            assert_eq!(findings.len(), 1, "{content}");
            assert_eq!(findings[0].rule, Rule::ProductionConsumerBundleBypass);
        }
    }

    #[test]
    fn scan_bypass_content_rejects_import_alias_and_split_infra_receiver() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            r#"
            use eventexec::{spawn_consumer_ackable_tx_subscriber as spawn_it};

            fn wire(pg: PgRuntimeDeps) {
                spawn_it();
                let infra = pg.infra();
                infra.inbox();
            }
            "#,
        );
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ProductionConsumerBundleBypass)
        );
    }

    #[test]
    fn scan_bypass_content_ignores_strings_and_comments() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            r#"
            // spawn_consumer();
            const NOTE: &str = "pg.infra().inbox()";
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn domain_roots_include_all_layer_domain_crates() {
        let roots = domain_crate_roots();
        assert_eq!(
            roots,
            vec![
                "crates/identity",
                "crates/settings",
                "crates/audit",
                "crates/contractreg",
                "crates/syshealth",
            ]
        );
    }

    #[test]
    fn scan_domain_content_rejects_bypass_in_contractreg_and_syshealth() {
        for path in [
            Path::new("crates/contractreg/src/lib.rs"),
            Path::new("crates/syshealth/src/lib.rs"),
        ] {
            let findings = scan_domain_content(path, "let _ = pg.infra().inbox();");
            assert_eq!(findings.len(), 1, "{path:?}");
            assert_eq!(findings[0].rule, Rule::DomainConsumerBundleBypass);
        }
    }

    #[test]
    fn scan_domain_content_rejects_managed_worker_in_every_domain_crate() {
        for root in domain_crate_roots() {
            let path = Path::new(&root).join("src/lib.rs");
            let findings =
                scan_domain_content(&path, "let _ = eventexec::ManagedBlockingWorker::spawn;");
            assert_eq!(findings.len(), 1, "{path:?}");
            assert_eq!(findings[0].rule, Rule::DomainConsumerBundleBypass);
        }
    }

    #[test]
    fn scan_bypass_content_accepts_registered_fault_matrix_inbox_harness() {
        let findings = scan_bypass_content(
            Path::new("adapters/postgres/src/fault_matrix.rs"),
            r#"
            const MARKER: &str = "CONSISTENCY-FAULT-MATRIX-SEAM-01";
            async fn a(&self) { let store = self.deps.infra().inbox(); }
            async fn b(&self) { let store = self.deps.infra().inbox(); }
            async fn c(&self) { let store = self.deps.infra().inbox(); }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn production_bypass_allowlist_does_not_skip_fault_matrix_file() {
        assert!(
            !BYPASS_ALLOWED_PATHS.contains(&"adapters/postgres/src/fault_matrix.rs"),
            "fault_matrix.rs must use site-level exceptions so new bypasses are still scanned"
        );
    }

    #[test]
    fn scan_bypass_content_rejects_extra_fault_matrix_inbox_harness() {
        let findings = scan_bypass_content(
            Path::new("adapters/postgres/src/fault_matrix.rs"),
            r#"
            const MARKER: &str = "CONSISTENCY-FAULT-MATRIX-SEAM-01";
            async fn a(&self) { let store = self.deps.infra().inbox(); }
            async fn b(&self) { let store = self.deps.infra().inbox(); }
            async fn c(&self) { let store = self.deps.infra().inbox(); }
            async fn d(&self) { let store = self.deps.infra().inbox(); }
            "#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::ProductionConsumerBundleBypass);
    }

    #[derive(Clone, Copy)]
    struct ClaimCutoverFixture {
        path: &'static str,
        content: &'static str,
    }

    impl ClaimCutoverFixture {
        const fn new(path: &'static str, content: &'static str) -> Self {
            Self { path, content }
        }
    }

    fn scan_claim_cutover_fixtures(fixtures: &[ClaimCutoverFixture]) -> Vec<Finding<Rule>> {
        let sources = fixtures
            .iter()
            .map(|fixture| (PathBuf::from(fixture.path), fixture.content.to_string()))
            .collect::<Vec<_>>();
        scan_outbox_claim_cutover_sources(&sources)
    }

    fn relay_provider_fixture(imports: &str, relay: &str, provider: &str) -> String {
        format!(
            r#"
            {imports}
            use consistency::{{Disposition, EngineError, OutboxMetricSubject}};
            use vocab::DomainName;
            struct {provider};
            impl {relay} for {provider} {{
                type Claim = ();
                fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject {{ todo!() }}
                fn claim_domain(&self) -> &DomainName {{ todo!() }}
                async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {{
                    todo!()
                }}
                async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {{
                    todo!()
                }}
            }}
            "#,
        )
    }

    #[test]
    fn outbox_claim_cutover_synthetic_red_rejects_legacy_production_paths() {
        let cases = [
            (
                "rogue production relay provider",
                ClaimCutoverFixture::new(
                    "crates/identity/src/rogue_outbox.rs",
                    r#"
                    use consistency::{Disposition, EngineError, OutboxMetricSubject, OutboxRelay};
                    use vocab::DomainName;
                    struct RogueOutbox;
                    impl OutboxRelay for RogueOutbox {
                        type Claim = ();
                        fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject { todo!() }
                        fn claim_domain(&self) -> &DomainName { todo!() }
                        async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {
                            todo!()
                        }
                        async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {
                            todo!()
                        }
                    }
                    "#,
                ),
            ),
            (
                "aliased rogue relay provider in composition",
                ClaimCutoverFixture::new(
                    "composition/identity/src/lib.rs",
                    r#"
                    use consistency::{Disposition, EngineError, OutboxMetricSubject};
                    use consistency::OutboxRelay as ClaimedRelay;
                    use vocab::DomainName;
                    struct RogueOutbox;
                    impl ClaimedRelay for RogueOutbox {
                        type Claim = ();
                        fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject { todo!() }
                        fn claim_domain(&self) -> &DomainName { todo!() }
                        async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {
                            todo!()
                        }
                        async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {
                            todo!()
                        }
                    }
                    "#,
                ),
            ),
            (
                "legacy source trait",
                ClaimCutoverFixture::new(
                    "crates/consistency/src/outbox.rs",
                    r#"
                    pub trait OutboxSource {
                        type Claim;
                        async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError>;
                    }
                    "#,
                ),
            ),
            (
                "eventexec split poll acquire seam",
                ClaimCutoverFixture::new(
                    "crates/eventexec/src/relay.rs",
                    r#"
                    async fn relay_tick<A: OutboxSource + OutboxRelay>(outbox: &A) {
                        let pending = outbox.poll_pending(100).await?;
                        for entry in pending {
                            if outbox.acquire_lease(entry.event_id()).await? {
                                outbox.relay(entry).await?;
                            }
                        }
                    }
                    "#,
                ),
            ),
            (
                "runtime relay wiring bypass",
                ClaimCutoverFixture::new(
                    "assemblies/runtime/src/event_transport.rs",
                    r#"
                    fn wire_domain_relay(
                        outbox: postgres::PgOutbox,
                        module: &mut DomainModuleResult,
                    ) {
                        module.workers.push(Box::new(move |token| {
                            DynManagedResource::new_box(relay_loop(Arc::new(outbox), token))
                        }));
                    }
                    "#,
                ),
            ),
        ];

        for (name, fixture) in cases {
            let findings = scan_claim_cutover_fixtures(&[fixture]);
            assert!(
                !findings.is_empty(),
                "synthetic red `{name}` was not detected"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_resolves_canonical_trait_identity() {
        let crate_alias = relay_provider_fixture(
            "use consistency as c; use c::OutboxRelay as Relay;",
            "Relay",
            "AliasedRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/aliased.rs"),
            crate_alias,
        )]);
        assert!(!findings.is_empty(), "crate alias hid rogue provider");

        let reexported =
            relay_provider_fixture("use crate::RelayPort;", "RelayPort", "ReexportedRogue");
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "pub use consistency::OutboxRelay as RelayPort; mod rogue;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), reexported),
        ]);
        assert!(!findings.is_empty(), "crate re-export hid rogue provider");
    }

    #[test]
    fn outbox_claim_cutover_resolves_native_private_and_cargo_alias_paths() {
        let native =
            relay_provider_fixture("", "consistency::outbox::OutboxRelay", "NativePathRogue");
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/native.rs"),
            native,
        )]);
        assert!(
            !findings.is_empty(),
            "native module path hid rogue provider"
        );

        let private = relay_provider_fixture(
            "use super::OutboxRelay;",
            "OutboxRelay",
            "PrivateImportRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "use consistency::OutboxRelay; mod rogue;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), private),
        ]);
        assert!(
            !findings.is_empty(),
            "private parent import hid rogue provider"
        );

        let cargo_alias = relay_provider_fixture(
            "use relay_engine::OutboxRelay;",
            "OutboxRelay",
            "CargoAliasRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/Cargo.toml"),
                r#"[dependencies]
                relay_engine = { package = "consistency", path = "../consistency" }
                "#
                .to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), cargo_alias),
        ]);
        assert!(
            !findings.is_empty(),
            "Cargo dependency alias hid rogue provider"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_macro_generated_relay_impl() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            macro_rules! impl_relay {
                ($provider:ty) => { impl OutboxRelay for $provider {} };
            }
            struct MacroRogue;
            impl_relay!(MacroRogue);
            "#
            .to_string(),
        )]);
        assert!(
            !findings.is_empty(),
            "macro-generated rogue provider passed"
        );
    }

    #[test]
    fn outbox_claim_cutover_allows_unused_relay_impl_macro_definition() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            macro_rules! impl_relay {
                ($provider:ty) => { impl OutboxRelay for $provider {} };
            }
            struct Unused;
            "#
            .to_string(),
        )]);
        assert!(
            findings.is_empty(),
            "unused macro definition was rejected: {findings:#?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_external_impl_macro_invocation() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            struct ExternalRogue;
            external_macros::impl_outbox_relay!(ExternalRogue);
            "#
            .to_string(),
        )]);
        assert!(
            !findings.is_empty(),
            "external impl macro invocation passed"
        );
    }

    #[test]
    fn outbox_claim_cutover_resolves_module_qualified_export_graph() {
        let cases = [
            (
                "nested re-export imported across files",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::ports::RelayPort;",
                    "RelayPort",
                    "ImportedRogue",
                ),
            ),
            (
                "fixed-point nested re-export",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                pub mod api {
                    pub use crate::ports::RelayPort as PublicRelay;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::PublicRelay;",
                    "PublicRelay",
                    "FixedPointRogue",
                ),
            ),
            (
                "self-relative nested re-export",
                r#"
                pub mod api {
                    pub mod ports {
                        pub use consistency::OutboxRelay as RelayPort;
                    }
                    pub use self::ports::RelayPort as SelfRelay;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::SelfRelay;",
                    "SelfRelay",
                    "SelfRelativeRogue",
                ),
            ),
            (
                "multi-super nested re-export",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                pub mod api {
                    pub mod nested {
                        pub use super::super::ports::RelayPort as DeepRelay;
                    }
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::nested::DeepRelay;",
                    "DeepRelay",
                    "SuperRelativeRogue",
                ),
            ),
            (
                "qualified impl path",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture("", "crate::ports::RelayPort", "QualifiedRogue"),
            ),
            (
                "glob from canonical export module",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture("use crate::ports::*;", "RelayPort", "GlobRogue"),
            ),
        ];

        for (name, lib, rogue) in cases {
            let findings = scan_outbox_claim_cutover_sources(&[
                (PathBuf::from("crates/identity/src/lib.rs"), lib.to_string()),
                (PathBuf::from("crates/identity/src/rogue.rs"), rogue),
            ]);
            assert!(!findings.is_empty(), "module export red `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_does_not_confuse_unrelated_same_named_traits() {
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/local.rs"),
                r#"
                trait OutboxRelay {}
                struct LocalRelay;
                impl OutboxRelay for LocalRelay {}
                "#
                .to_string(),
            ),
            (
                PathBuf::from("crates/identity/src/other.rs"),
                r#"
                mod other { pub trait OutboxRelay {} }
                use other::OutboxRelay as OtherRelay;
                struct OtherProvider;
                impl OtherRelay for OtherProvider {}

                mod nested {
                    pub mod ports { pub trait RelayPort {} }
                }
                use nested::ports::RelayPort;
                struct NestedOtherProvider;
                impl RelayPort for NestedOtherProvider {}
                "#
                .to_string(),
            ),
        ]);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn outbox_claim_cutover_scans_modules_named_tests_without_cfg() {
        let content = format!(
            "mod tests {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "ProductionRogue",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            content,
        )]);
        assert!(!findings.is_empty(), "uncfg'd `mod tests` was skipped");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn outbox_claim_source_set_includes_test_named_production_files() {
        static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("rss-outbox-guard-{}-{nonce}", std::process::id()));
        let src = root.join("crates/demo/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\"]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(src.join("lib.rs"), "pub mod worker_tests;\n").unwrap();
        std::fs::write(src.join("worker_tests.rs"), "pub fn production() {}\n").unwrap();

        let files = workspace_member_source_files(&root).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            files.iter().any(|path| path.ends_with("worker_tests.rs")),
            "production file was excluded by its name: {files:?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_excludes_only_parent_cfg_test_external_modules() {
        let test_provider = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "TestOnlyRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(test)] mod test_support;".to_string(),
            ),
            (
                PathBuf::from("crates/identity/src/test_support.rs"),
                test_provider,
            ),
        ]);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn outbox_claim_cutover_scans_external_module_with_any_production_reachability() {
        let provider = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ProductionReachableRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                r#"
                #[cfg(test)]
                mod relay;
                #[cfg(not(test))]
                mod relay;
                "#
                .to_string(),
            ),
            (PathBuf::from("crates/identity/src/relay.rs"), provider),
        ]);
        assert!(
            !findings.is_empty(),
            "production-reachable external module was excluded"
        );
    }

    #[test]
    fn outbox_claim_cutover_cfg_test_implication_is_structural() {
        let all_test = format!(
            "#[cfg(all(test, feature = \"fixture\"))] mod support {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "AllTestRelay",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            all_test,
        )]);
        assert!(findings.is_empty(), "cfg(all(test, ..)) must be test-only");

        let any_test = format!(
            "#[cfg(any(test, feature = \"production\"))] mod support {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "AnyTestRelay",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            any_test,
        )]);
        assert!(
            !findings.is_empty(),
            "cfg(any(test, production)) remains production-reachable"
        );

        let external = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ExternalAllTestRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(all(test, feature = \"fixture\"))] mod support;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/support.rs"), external),
        ]);
        assert!(
            findings.is_empty(),
            "external cfg(all(test, ..)) must be test-only: {findings:#?}"
        );

        let external = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ExternalAnyTestRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(any(test, feature = \"production\"))] mod support;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/support.rs"), external),
        ]);
        assert!(
            !findings.is_empty(),
            "external cfg(any(test, production)) remains production-reachable"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_disconnected_eventexec_bait() {
        let cases = [
            (
                "relay helper is never called",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claims) = store.claim_batch(batch).await else { return };
                    fn nested_bait<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                        drop(relay_batch(store, claims));
                    }
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "claim result is replaced before relay_batch",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    let unrelated = Vec::new();
                    relay_batch(store, unrelated).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay consumes a different value",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(other).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch call only exists in a dead closure",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    let _dead = || relay_batch(store, claimed);
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch future is dropped",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    drop(relay_batch(store, claimed));
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch exists only in a dead branch",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    if false { relay_batch(store, claimed).await; }
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay future is dropped inside the map",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        drop(store.relay(claim));
                    })).await;
                }
                "#,
            ),
            (
                "awaited relay is not the closure tail value",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        let _discarded = store.relay(claim).await;
                    })).await;
                }
                "#,
            ),
            (
                "join_all future is dropped",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    drop(futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })));
                }
                "#,
            ),
            (
                "claim_batch is not awaited",
                r#"
                trait SyncRelay {
                    type Claim;
                    fn claim_batch(&self, limit: usize) -> Vec<Self::Claim>;
                    async fn relay(&self, claim: Self::Claim);
                }
                async fn relay_domain_once<A: SyncRelay>(store: &Arc<A>, batch: usize) {
                    let claimed = store.claim_batch(batch);
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: SyncRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "join_all input is not a map pipeline",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims).await;
                }
                "#,
            ),
            (
                "map has more than one callback argument",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(
                        |claim| async move { store.relay(claim).await },
                        other,
                    )).await;
                }
                "#,
            ),
            (
                "map receiver does not consume the claim vector",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "into_iter call has an argument",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter(other).map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "map closure has multiple inputs",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim, extra| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "map closure body is not an async future",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(
                        claims.into_iter().map(|claim| store.relay(claim)),
                    ).await;
                }
                "#,
            ),
        ];

        for (name, content) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                EVENTEXEC_RELAY_PATH,
                content,
            )]);
            assert!(!findings.is_empty(), "disconnected bait `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_disconnected_runtime_bait() {
        let cases = [
            (
                "relay worker uses phase-one policy",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker = WorkerSpec::observational_phase_one(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    module.push_worker(worker);
                }
                "#,
            ),
            (
                "wrong outbox parameter type",
                r#"
                fn wire_domain_relay(outbox: RogueOutbox, module: &mut DomainModuleResult) {
                    let worker = WorkerSpec::observational_deferred(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
            (
                "spawn call is nested dead bait",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        let _dead = || spawn_relay(name, outbox, token);
                        DynManagedResource::new_box(other_worker(token))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
            (
                "worker is never registered or returned",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    let _discarded = worker;
                }
                "#,
            ),
            (
                "worker registration is conditional",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    if false { module.workers.push(worker); }
                }
                "#,
            ),
            (
                "spawn relay is wrapped by another tail call",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(other(spawn_relay(name, outbox, token)))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
        ];

        for (name, content) in cases {
            let findings =
                scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(TARGET, content)]);
            assert!(!findings.is_empty(), "runtime bait `{name}` passed");
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn outbox_claim_source_set_includes_composition_members() {
        let root = workspace_root().unwrap();
        let sources = load_outbox_claim_cutover_sources(&root).unwrap();
        let paths = sources
            .iter()
            .map(|(path, _)| path.as_path())
            .collect::<BTreeSet<_>>();
        for path in [
            "composition/settings/src/lib.rs",
            "composition/identity/src/lib.rs",
            "composition/audit/src/lib.rs",
        ] {
            assert!(
                paths.contains(Path::new(path)),
                "missing shipped source {path}"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_synthetic_red_rejects_retired_sql_after_0057() {
        let cases = [
            (
                "CREATE poll_pending",
                "CREATE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint) RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;",
            ),
            (
                "ALTER poll_pending",
                "ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_outbox_maintenance;",
            ),
            (
                "GRANT poll_pending",
                "GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app;",
            ),
            (
                "CREATE acquire_lease",
                "CREATE FUNCTION rss_outbox_acquire_lease(p_event_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;",
            ),
            (
                "ALTER acquire_lease",
                "ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_outbox_maintenance;",
            ),
            (
                "GRANT acquire_lease",
                "GRANT EXECUTE ON FUNCTION rss_outbox_acquire_lease(text) TO rss_app;",
            ),
        ];

        for (name, sql) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_rogue_legacy_outbox_function.sql",
                sql,
            )]);
            assert!(
                !findings.is_empty(),
                "synthetic red `{name}` was not detected"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_whitespace_delimited_retired_ddl() {
        for separator in ["\n", "\t", "\r\n"] {
            let sql = format!(
                "CREATE{separator}FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1';"
            );
            let sources = vec![(
                PathBuf::from("adapters/postgres/migrations/0062_whitespace_legacy.sql"),
                sql,
            )];
            let findings = scan_outbox_claim_cutover_sources(&sources);
            assert!(
                !findings.is_empty(),
                "whitespace-delimited retired DDL passed for {separator:?}"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_sqlx_retired_function_calls() {
        let cases = [
            r#"fn load() { sqlx::query("SELECT * FROM rss_outbox_poll_pending($1, $2)"); }"#,
            r#"fn load() { sqlx::query_as!(Row, "SELECT rss_outbox_acquire_lease($1)"); }"#,
            r#"use sqlx::query as q; fn load() { q("SELECT * FROM rss_outbox_poll_pending($1, $2)"); }"#,
            r#"use sqlx::query_as as qa; fn load() { qa!(Row, "SELECT rss_outbox_acquire_lease($1)"); }"#,
        ];
        for content in cases {
            let findings = scan_outbox_claim_cutover_sources(&[(
                PathBuf::from("adapters/postgres/src/rogue.rs"),
                content.to_string(),
            )]);
            assert!(!findings.is_empty(), "sqlx retired call passed: {content}");
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_non_literal_dynamic_execute() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_dynamic_variable.sql",
            r#"
            DO $do$
            DECLARE ddl text := 'CREATE FUNCTION rss_outbox_poll_pending(text, bigint)';
            BEGIN
                EXECUTE ddl;
            END
            $do$;
            "#,
        )]);
        assert!(!findings.is_empty(), "non-literal dynamic EXECUTE passed");
    }

    #[test]
    fn outbox_claim_cutover_allows_unrelated_legacy_identifiers() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "crates/identity/src/local_queue.rs",
            r#"
            struct PendingEntry;
            trait OutboxSource {}
            fn poll_pending() {}
            fn load(source: Queue) { source.poll_pending(); }
            "#,
        )]);
        assert!(
            findings.is_empty(),
            "unrelated names were rejected: {findings:#?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_requires_both_0057_retirement_witnesses() {
        let cases = [
            (
                "missing poll_pending DROP",
                "DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);",
                "rss_outbox_poll_pending",
            ),
            (
                "missing acquire_lease DROP",
                "DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);",
                "rss_outbox_acquire_lease",
            ),
            (
                "ALTER does not witness retirement",
                "ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_app;\nDROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);",
                "rss_outbox_poll_pending",
            ),
        ];
        for (name, sql, missing) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
                sql,
            )]);
            assert!(
                findings.iter().any(|finding| {
                    finding.detail.contains("0057 必须显式 DROP")
                        && finding.detail.contains(missing)
                }),
                "0057 witness red `{name}` passed: {findings:#?}"
            );
        }

        let quoted = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
            r#"
            DROP FUNCTION IF EXISTS "rss_outbox_poll_pending" ( text , bigint );
            DROP FUNCTION IF EXISTS "rss_outbox_acquire_lease" ( text );
            "#,
        )]);
        assert!(quoted.is_empty(), "{quoted:#?}");
    }

    #[test]
    fn outbox_claim_cutover_rust_findings_preserve_each_source_line() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "crates/identity/src/rogue_outbox.rs",
            "fn first() {\n    outbox.poll_pending();\n}\nfn second() {\n    outbox.poll_pending();\n}\n",
        )]);
        let poll = findings
            .iter()
            .filter(|finding| finding.detail.contains("`poll_pending`"))
            .collect::<Vec<_>>();
        assert_eq!(poll.len(), 2, "{findings:#?}");
        assert_eq!(poll[0].subject, "crates/identity/src/rogue_outbox.rs:2");
        assert_eq!(poll[1].subject, "crates/identity/src/rogue_outbox.rs:5");
    }

    #[test]
    fn outbox_claim_cutover_sql_findings_preserve_statement_and_execute_lines() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_located_legacy.sql",
            r#"CREATE FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1';
ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app;
DO $do$
BEGIN
    EXECUTE $ddl$GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app$ddl$;
END
$do$;
"#,
        )]);
        assert_eq!(findings.len(), 3, "{findings:#?}");
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.subject.as_str())
                .collect::<Vec<_>>(),
            [
                "adapters/postgres/migrations/0062_located_legacy.sql:1",
                "adapters/postgres/migrations/0062_located_legacy.sql:2",
                "adapters/postgres/migrations/0062_located_legacy.sql:5",
            ]
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_quoted_and_dynamic_retired_sql() {
        let cases = [
            (
                "quoted CREATE",
                r#"CREATE FUNCTION "rss_outbox_poll_pending"(text, bigint) RETURNS bigint LANGUAGE sql AS $$ SELECT 1 $$;"#,
            ),
            (
                "schema-qualified quoted ALTER",
                r#"ALTER FUNCTION "public"."rss_outbox_acquire_lease"(text) OWNER TO rss_app;"#,
            ),
            (
                "schema-qualified quoted GRANT",
                r#"GRANT EXECUTE ON FUNCTION public."rss_outbox_poll_pending"(text, bigint) TO rss_app;"#,
            ),
            (
                "DO EXECUTE literal",
                r#"DO $$ BEGIN EXECUTE 'CREATE FUNCTION rss_outbox_acquire_lease(text) RETURNS boolean LANGUAGE sql AS ''SELECT true'''; END $$;"#,
            ),
            (
                "DO EXECUTE format",
                r#"DO $$ BEGIN EXECUTE format('ALTER FUNCTION public.%I(text) OWNER TO rss_app', 'rss_outbox_acquire_lease'); END $$;"#,
            ),
            (
                "DO EXECUTE untagged dollar literal",
                r#"DO $do$ BEGIN EXECUTE $$CREATE FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1'$$; END $do$;"#,
            ),
            (
                "DO EXECUTE format with tagged dollar literals",
                r#"DO $do$ BEGIN EXECUTE format($fmt$ALTER FUNCTION public.%I(text) OWNER TO rss_app$fmt$, $name$rss_outbox_acquire_lease$name$); END $do$;"#,
            ),
        ];

        for (name, sql) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_dynamic_legacy_outbox.sql",
                sql,
            )]);
            assert!(!findings.is_empty(), "retired SQL `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_dynamic_sql_respects_dollar_literal_state() {
        let inert = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_inert_nested_execute.sql",
            r#"
            DO $do$
            BEGIN
                PERFORM $text$
                    EXECUTE $ddl$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$ddl$;
                $text$;
            END
            $do$;
            "#,
        )]);
        assert!(
            inert.is_empty(),
            "nested dollar literal executed: {inert:#?}"
        );

        let executable = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_real_dollar_execute.sql",
            r#"
            DO $do$
            BEGIN
                EXECUTE $ddl$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$ddl$;
            END
            $do$;
            "#,
        )]);
        assert!(
            !executable.is_empty(),
            "real dollar-quoted EXECUTE was not detected"
        );

        let function_body = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_function_dollar_execute.sql",
            r#"
            CREATE FUNCTION rss_outbox_current() RETURNS void AS $body$
            BEGIN
                EXECUTE $ddl$ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app$ddl$;
            END
            $body$ LANGUAGE plpgsql;
            "#,
        )]);
        assert!(
            !function_body.is_empty(),
            "function-body dollar EXECUTE was not detected"
        );
    }

    #[test]
    fn outbox_claim_cutover_accepts_canonical_and_non_production_bait() {
        let fixtures = [
            ClaimCutoverFixture::new(
                "crates/consistency/src/outbox.rs",
                r#"
                pub trait OutboxRelay {
                    type Claim;
                    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject;
                    fn claim_domain(&self) -> &DomainName;
                    async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError>;
                    async fn relay(&self, claim: Self::Claim) -> Result<Disposition, EngineError>;
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/src/outbox.rs",
                r#"
                use consistency::OutboxRelay;
                impl OutboxRelay for PgOutbox {
                    type Claim = PgClaimedOutboxEntry;
                    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject { &claim.subject }
                    fn claim_domain(&self) -> &DomainName { &self.domain }
                    async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError> {
                        claim_batch(&self.pool, &self.domain, limit).await
                    }
                    async fn relay(&self, claim: Self::Claim) -> Result<Disposition, EngineError> {
                        settle_claim(&self.pool, claim).await
                    }
                }

                // Bait only: impl OutboxRelay for RogueOutbox; trait OutboxSource; poll_pending();
                const MIGRATION_NOTE: &str = "CREATE FUNCTION rss_outbox_acquire_lease(text)";
                #[cfg(test)]
                mod tests {
                    struct FakeOutbox;
                    impl OutboxRelay for FakeOutbox { type Claim = FakeClaim; }
                    trait OutboxSource {}
                    fn old_fake_seam() { poll_pending(); acquire_lease(); }
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "crates/eventexec/src/relay.rs",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let claim_result = store.claim_batch(batch).await;
                    let claims = match claim_result {
                        Ok(claims) => claims,
                        Err(error) => return error,
                    };
                    relay_batch(store, claims).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "assemblies/runtime/src/event_transport.rs",
                r#"
                fn wire_domain_relay(
                    outbox: postgres::PgOutbox,
                    module: &mut DomainModuleResult,
                ) -> anyhow::Result<()> {
                    let worker = WorkerSpec::relay_deferred(
                        "outbox-relay:test",
                        &admission,
                        move |token, relay_admission| {
                        DynManagedResource::new_box(spawn_relay(
                            worker_name,
                            outbox,
                            relay_cfg,
                            clock,
                            token,
                            health,
                            metrics,
                            relay_admission,
                        ))
                    });
                    module.push_worker(worker);
                    Ok(())
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "crates/saga/src/store.rs",
                "impl SagaStore for PgSagaStore { async fn acquire_lease(&self, saga_id: SagaId) {} }",
            ),
            ClaimCutoverFixture::new(
                "crates/reconcile/src/store.rs",
                "impl ReconcileStore for PgReconcileStore { async fn acquire_lease(&self, action_id: ActionId) {} }",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0031_harden_outbox_tenant_scope.sql",
                "CREATE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint) RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0036_add_outbox_schema_columns.sql",
                "CREATE FUNCTION rss_outbox_acquire_lease(p_event_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0037_outbox_metric_scope_functions.sql",
                "-- Historical migration intentionally remains immutable.",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
                r#"
                DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);
                DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);
                CREATE FUNCTION rss_outbox_claim_batch(p_domain text, p_limit bigint)
                RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_comment_bait.sql",
                r#"
                -- CREATE FUNCTION rss_outbox_poll_pending(text, bigint)
                /* ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app; */
                SELECT 'GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app';
                CREATE FUNCTION rss_outbox_current() RETURNS void LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE NOTICE 'CREATE FUNCTION rss_outbox_acquire_lease(text)';
                    PERFORM format('GRANT EXECUTE ON FUNCTION %I', 'rss_outbox_poll_pending');
                    -- EXECUTE 'ALTER FUNCTION rss_outbox_acquire_lease(text)';
                END
                $$;
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0063_inert_dollar_bait.sql",
                r#"
                DO $do$
                BEGIN
                    PERFORM $sql$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$sql$;
                END
                $do$;
                "#,
            ),
        ];

        let findings = scan_claim_cutover_fixtures(&fixtures);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: governance test fixture 必须能读取当前 workspace；失败即测试环境/仓库布局错误。
    fn relay_budget_guard_accepts_canonical_workspace() {
        let root = workspace_root().expect("workspace root");
        let sources = load_relay_budget_sources(&root).expect("relay budget sources");
        let findings = scan_relay_budget_sources(&sources);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settlement_funnel_guard_accepts_canonical_workspace() {
        let root = workspace_root().expect("workspace root");
        let sources = load_outbox_claim_cutover_sources(&root).expect("workspace sources");
        let scan = scan_settlement_funnel_sources(&sources);
        assert!(scan.findings.is_empty(), "{:#?}", scan.findings);
        assert_eq!(
            scan.canonical_calls,
            BTreeSet::from([
                "rss_outbox_mark_dlx".to_string(),
                "rss_outbox_settle_published".to_string(),
                "rss_outbox_settle_retry".to_string(),
            ]),
            "canonical settlement module must exercise every raw SQL function"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settlement_capability_and_raw_sql_funnel_have_distinct_strength_ids() {
        let root = workspace_root().expect("workspace root");
        let capability =
            std::fs::read_to_string(root.join("adapters/postgres/src/outbox/settlement.rs"))
                .expect("private settlement module");
        let raw_sql_guard =
            std::fs::read_to_string(root.join("xtask/src/event_transport_guard.rs"))
                .expect("raw SQL funnel guard");

        assert!(
            capability.contains("INVARIANT: PG-OUTBOX-SETTLEMENT-CAPABILITY-01 { level = \"Hard\""),
            "native capability boundary must have its own Hard invariant ID"
        );
        assert!(
            raw_sql_guard
                .contains("INVARIANT: PG-OUTBOX-SETTLEMENT-FUNNEL-01 { level = \"Medium\""),
            "workspace raw SQL funnel must remain honestly Medium"
        );
        assert!(
            !capability.contains("INVARIANT: PG-OUTBOX-SETTLEMENT-FUNNEL-01 { level = \"Hard\""),
            "the Medium workspace policy must not be advertised as native Hard"
        );
    }

    #[test]
    fn settlement_funnel_guard_synthetic_red_rejects_each_raw_function_and_query_path() {
        let cases = [
            (
                "rss_outbox_settle_published",
                r#"async fn bypass(c: &mut C) { sqlx::query("SELECT rss_outbox_settle_published($1, $2, $3)").execute(c).await; }"#,
            ),
            (
                "rss_outbox_settle_retry",
                r#"async fn bypass(c: &mut C) { sqlx::query_scalar("SELECT rss_outbox_settle_retry($1, $2, $3)").fetch_one(c).await; }"#,
            ),
            (
                "rss_outbox_mark_dlx",
                r#"async fn bypass(c: &mut C) { sqlx::query_as!(Row, "SELECT * FROM rss_outbox_mark_dlx($1, $2, $3)").fetch_one(c).await; }"#,
            ),
            (
                "rss_outbox_settle_published",
                r#"const SQL: &str = "SELECT rss_outbox_settle_published($1, $2, $3)"; async fn bypass(c: &mut C) { sqlx::query(SQL).execute(c).await; }"#,
            ),
            (
                "rss_outbox_settle_retry",
                r#"async fn bypass(c: &mut C) { let sql = "SELECT rss_outbox_settle_retry($1, $2, $3)"; sqlx::query(sql).execute(c).await; }"#,
            ),
            (
                "rss_outbox_settle_force",
                r#"async fn bypass(c: &mut C) { sqlx::query("SELECT rss_outbox_settle_force($1)").execute(c).await; }"#,
            ),
        ];
        for (function, content) in cases {
            let sources = vec![(
                PathBuf::from("adapters/postgres/src/settlement_bypass.rs"),
                content.to_string(),
            )];
            let scan = scan_settlement_funnel_sources(&sources);
            let bypasses = scan
                .findings
                .iter()
                .filter(|finding| finding.subject.contains("settlement_bypass.rs"))
                .collect::<Vec<_>>();
            assert_eq!(bypasses.len(), 1, "{function}: {:#?}", scan.findings);
            assert!(bypasses[0].detail.contains(function));
        }
    }

    #[test]
    fn settlement_funnel_counts_only_awaited_sqlx_execution_and_folds_concat() {
        let outside = PathBuf::from("adapters/postgres/src/settlement_bypass.rs");
        let inert = scan_settlement_funnel_sources(&[(
            outside.clone(),
            r#"
                fn bait() {
                    drop("SELECT rss_outbox_settle_published($1, $2, $3)");
                    let _query = sqlx::query("SELECT rss_outbox_settle_retry($1, $2, $3)");
                }
            "#
            .to_string(),
        )]);
        assert!(
            inert
                .findings
                .iter()
                .all(|finding| !finding.subject.contains("settlement_bypass.rs")),
            "arbitrary strings and unawaited builders are not execution witnesses: {:#?}",
            inert.findings
        );

        let executed = scan_settlement_funnel_sources(&[(
            outside,
            r#"
                async fn bypass(connection: &mut sqlx::PgConnection) {
                    let sql = concat!("SELECT ", "rss_outbox_settle_published", "($1, $2, $3)");
                    let query = sqlx::query(sql).bind("event");
                    query.execute(connection).await.unwrap();
                }
            "#
            .to_string(),
        )]);
        assert!(
            executed.findings.iter().any(|finding| {
                finding.subject.contains("settlement_bypass.rs")
                    && finding.detail.contains("rss_outbox_settle_published")
            }),
            "awaited SQLx execution with literal concat must be rejected: {:#?}",
            executed.findings
        );
    }

    #[test]
    fn settlement_funnel_canonical_witness_requires_awaited_terminal() {
        let unawaited = scan_settlement_funnel_sources(&[(
            PathBuf::from(POSTGRES_OUTBOX_SETTLEMENT_PATH),
            r#"
                fn bait() {
                    let _query = sqlx::query(
                        "SELECT rss_outbox_settle_published($1, $2, $3)"
                    );
                }
            "#
            .to_string(),
        )]);
        assert!(
            !unawaited
                .canonical_calls
                .contains("rss_outbox_settle_published"),
            "constructing a query without execute/fetch await must not satisfy anti-vacuity"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settlement_funnel_guard_canonical_anti_vacuity_rejects_string_bait() {
        let absent = scan_settlement_funnel_sources(&[]);
        assert_eq!(
            absent.findings.len(),
            OUTBOX_SETTLEMENT_RAW_FUNCTIONS.len(),
            "absent canonical module must fail closed"
        );
        let root = workspace_root().expect("workspace root");
        let mut sources = load_outbox_claim_cutover_sources(&root).expect("workspace sources");
        let (_, settlement) = sources
            .iter_mut()
            .find(|(path, _)| path == Path::new(POSTGRES_OUTBOX_SETTLEMENT_PATH))
            .expect("closed settlement SQL façade");
        assert!(settlement.contains("OutboxCallableRoutine::SettlePublished.sql()"));
        let unknown_family = settlement.replacen(
            "OutboxCallableRoutine::SettlePublished.sql()",
            "OutboxCallableRoutine::SettleForce.sql()",
            1,
        );
        let unknown_scan = scan_settlement_funnel_sources(&[(
            PathBuf::from(POSTGRES_OUTBOX_SETTLEMENT_PATH),
            unknown_family,
        )]);
        assert!(
            unknown_scan.findings.iter().any(|finding| finding
                .detail
                .contains("canonical raw function `rss_outbox_settle_published`")),
            "private module must fail closed when the typed settlement witness changes: {:#?}",
            unknown_scan.findings
        );
        *settlement = settlement.replacen(
            "OutboxCallableRoutine::SettlePublished.sql()",
            "OutboxCallableRoutine::SettlePublishedBroken.sql()",
            1,
        );
        settlement
            .push_str(r#"\nconst SETTLEMENT_STRING_BAIT: &str = "rss_outbox_settle_published";\n"#);
        let scan = scan_settlement_funnel_sources(&sources);
        assert!(
            scan.findings.iter().any(|finding| finding
                .detail
                .contains("canonical raw function `rss_outbox_settle_published`")),
            "non-executable string bait must not satisfy anti-vacuity: {:#?}",
            scan.findings
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settlement_funnel_rejects_fake_receiver_and_catalog_identity_drift() {
        let root = workspace_root().expect("workspace root");
        let mut sources = load_outbox_claim_cutover_sources(&root).expect("workspace sources");
        let (_, settlement) = sources
            .iter_mut()
            .find(|(path, _)| path == Path::new(POSTGRES_OUTBOX_SETTLEMENT_PATH))
            .expect("closed settlement façade");
        *settlement = settlement.replacen(
            "crate::outbox_routine::OutboxCallableRoutine::SettlePublished.sql()",
            "fake::OutboxCallableRoutine::SettlePublished.sql()",
            1,
        );
        settlement
            .push_str("\n// crate::outbox_routine::OutboxCallableRoutine::SettlePublished.sql()\n");
        let fake_receiver = scan_settlement_funnel_sources(&sources);
        assert!(fake_receiver.findings.iter().any(|finding| {
            finding
                .detail
                .contains("canonical raw function `rss_outbox_settle_published`")
        }));

        let mut sources = load_outbox_claim_cutover_sources(&root).expect("workspace sources");
        let (_, catalog) = sources
            .iter_mut()
            .find(|(path, _)| path == Path::new(POSTGRES_OUTBOX_ROUTINE_CATALOG_PATH))
            .expect("typed outbox routine catalog");
        *catalog = catalog.replacen(
            "function: rss_outbox_settle_published",
            "function: rss_outbox_settle_published_broken",
            1,
        );
        let identity_drift = scan_settlement_funnel_sources(&sources);
        assert!(identity_drift.findings.iter().any(|finding| {
            finding
                .detail
                .contains("canonical raw function `rss_outbox_settle_published`")
        }));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relay_budget_guard_discovers_constructor_callsites_workspacewide() {
        let root = workspace_root().expect("workspace root");
        let mut sources = load_outbox_claim_cutover_sources(&root).expect("workspace sources");
        assert!(scan_relay_budget_constructor_callsites(&sources).is_empty());
        sources.push((
            PathBuf::from("crates/rogue/src/lib.rs"),
            "async fn rogue() { let _ = amqp::AmqpRuntimeDeps::connect(endpoint, name, timeout).await; }".to_string(),
        ));
        let findings = scan_relay_budget_constructor_callsites(&sources);
        assert!(findings.iter().any(|finding| {
            finding.subject == "crates/rogue/src/lib.rs"
                && finding.detail.contains("AmqpRuntimeDeps::connect")
        }));
    }

    #[derive(Clone, Copy)]
    enum RelayBudgetMutation<'a> {
        ReplaceAll { from: &'a str, to: &'a str },
        InsertAfter { needle: &'a str, addition: &'a str },
    }

    struct RelayBudgetRedCase<'a> {
        name: &'a str,
        path: &'a str,
        mutation: RelayBudgetMutation<'a>,
        expected: &'a [(&'a str, &'a str)],
        hardcode_detail: Option<&'a str>,
    }

    impl<'a> RelayBudgetRedCase<'a> {
        const fn replace(
            name: &'a str,
            path: &'a str,
            from: &'a str,
            to: &'a str,
            expected: &'a [(&'a str, &'a str)],
        ) -> Self {
            Self {
                name,
                path,
                mutation: RelayBudgetMutation::ReplaceAll { from, to },
                expected,
                hardcode_detail: None,
            }
        }

        const fn hardcode(
            name: &'a str,
            path: &'a str,
            needle: &'a str,
            addition: &'a str,
            hardcode_detail: &'a str,
        ) -> Self {
            Self {
                name,
                path,
                mutation: RelayBudgetMutation::InsertAfter { needle, addition },
                expected: &[],
                hardcode_detail: Some(hardcode_detail),
            }
        }
    }

    #[allow(clippy::panic)]
    // reason: test fixture corruption must fail with the exact mutation case/carrier context.
    fn assert_relay_budget_red_case(
        canonical_sources: &[(PathBuf, String)],
        case: &RelayBudgetRedCase<'_>,
    ) {
        let mut mutated_sources = canonical_sources.to_vec();
        let (_, content) = mutated_sources
            .iter_mut()
            .find(|(path, _)| path == Path::new(case.path))
            .unwrap_or_else(|| panic!("{}: missing carrier {}", case.name, case.path));
        match case.mutation {
            RelayBudgetMutation::ReplaceAll { from, to } => {
                assert!(
                    content.contains(from),
                    "{}: mutation source fragment missing: {from}",
                    case.name
                );
                *content = content.replace(from, to);
            }
            RelayBudgetMutation::InsertAfter { needle, addition } => {
                assert!(
                    content.contains(needle),
                    "{}: insertion anchor missing: {needle}",
                    case.name
                );
                *content = content.replacen(needle, &format!("{needle}{addition}"), 1);
            }
        }

        let expected = if let Some(detail) = case.hardcode_detail {
            let line = content
                .lines()
                .position(|line| line.contains("Duration::from_secs(40)"))
                .map(|index| index + 1)
                .unwrap_or_else(|| panic!("{}: hardcode mutation missing", case.name));
            vec![finding(
                Rule::OutboxRelayBudget,
                format!("{}:{line}", case.path),
                detail,
            )]
        } else {
            case.expected
                .iter()
                .map(|(subject, detail)| finding(Rule::OutboxRelayBudget, *subject, *detail))
                .collect()
        };
        let findings = scan_relay_budget_sources(&mutated_sources);
        assert_eq!(findings, expected, "synthetic-red case `{}`", case.name);
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: synthetic-red 从 canonical workspace 逐 mutation 破坏，读取失败即夹具错误。
    fn relay_budget_guard_synthetic_red_breaks_each_carrier() {
        let root = workspace_root().expect("workspace root");
        let sources = load_relay_budget_sources(&root).expect("relay budget sources");
        let cases = [
            RelayBudgetRedCase::replace(
                "typed budget operational ceiling",
                "crates/eventexec/src/relay_config.rs",
                "pub const RELAY_BUDGET_MAX_MILLIS: u64 = 86_400_000;",
                "pub const RELAY_BUDGET_MAX_MILLIS: u64 = 86_400_001;",
                &[(
                    "crates/eventexec/src/relay_config.rs",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `pub const RELAY_BUDGET_MAX_MILLIS: u64 = 86_400_000`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "runtime maximum plus one boundary",
                "assemblies/runtime/src/event_transport.rs",
                "(\"RSS_RELAY_LEASE_TTL_MS\", \"86400001\")",
                "(\"RSS_RELAY_LEASE_TTL_MS\", \"86400002\")",
                &[(
                    "assemblies/runtime/src/event_transport.rs",
                    "OUTBOX-RELAY-BUDGET-01 缺边界测试 fragment `(\"RSS_RELAY_LEASE_TTL_MS\", \"86400001\")`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "amqp operational ceiling",
                "adapters/amqp/src/publisher.rs",
                "const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_000;",
                "const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_001;",
                &[(
                    "adapters/amqp/src/publisher.rs",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_000`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres operational ceiling",
                "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
                "p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000",
                "p_lease_ttl_ms > 86400001 OR p_required_budget_ms > 86400001",
                &[(
                    "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres maximum plus one boundary",
                POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH,
                "Some(86_400_001)",
                "Some(86_400_002)",
                &[(
                    POSTGRES_OUTBOX_INTEGRATION_TESTS_PATH,
                    "OUTBOX-RELAY-BUDGET-01 缺边界测试 fragment `Some(86_400_001)`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "runtime typed carrier",
                "assemblies/runtime/src/event_transport.rs",
                "relay: RelayTiming",
                "relay_budget_ms: u64",
                &[(
                    "assemblies/runtime/src/event_transport.rs",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `relay: RelayTiming`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "runtime infra phase audit carrier",
                "assemblies/runtime/src/phase/infra.rs",
                "relay.required_budget_ms = relay_budget.required_budget_millis()",
                "relay.required_budget = relay_budget.required_budget_millis()",
                &[(
                    "assemblies/runtime/src/phase/infra.rs",
                    "审计事件 `runtime event transport budget loaded` 缺安全字段 `relay.required_budget_ms`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "amqp bundle carrier",
                "adapters/amqp/src/bundle.rs",
                "publish_timeout,\n                &ca,",
                "Duration::ZERO,\n                &ca,",
                &[(
                    "adapters/amqp/src/bundle.rs",
                    "OUTBOX-RELAY-BUDGET-01 live seam `AmqpRuntimeDeps::connect_with_private_ca` 未消费 canonical typed budget/deadline: [\"AmqpPublisher::connect_with_private_ca(&publisher_endpoint.0,format!(\\\"{name}-pub\\\"),publish_timeout,&ca)\"]",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres outbox carrier",
                "adapters/postgres/src/outbox.rs",
                "with_publisher_watchdog(deadline, self.relay_budget",
                "with_publisher_watchdog(deadline, RelayBudget::for_tests()",
                &[(
                    "adapters/postgres/src/outbox.rs",
                    "OUTBOX-RELAY-BUDGET-01 live seam `PgOutbox::publish_claimed_before` 未消费 canonical typed budget/deadline: [\"with_publisher_watchdog(deadline,self.relay_budget,self.publisher.publish(request))\"]",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres settlement tenant carrier",
                "adapters/postgres/src/outbox.rs",
                "settlement::published(&self.tenant_pool, &claimed, self.relay_budget)",
                "settlement::published(&self.pool, &claimed, self.relay_budget)",
                &[(
                    "adapters/postgres/src/outbox.rs",
                    "OUTBOX-RELAY-BUDGET-01 live seam `PgOutbox::relay` 未消费 canonical typed budget/deadline: [\"settlement::published(&self.tenant_pool,&claimed,self.relay_budget)\"]",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres scalar settlement deadline carrier",
                "adapters/postgres/src/outbox/settlement.rs",
                "tenant_pool\n            .outbox_deadline_write(",
                "pool\n            .deadline_global_transaction(",
                &[
                    (
                        "adapters/postgres/src/outbox/settlement.rs",
                        "OUTBOX-RELAY-BUDGET-01 live seam `execute_published` 未消费 canonical typed budget/deadline: [\"tenant_pool.outbox_deadline_write(infra_tenant_scope(tenant),deadline\"]",
                    ),
                    (
                        "adapters/postgres/src/outbox/settlement.rs",
                        "OUTBOX-RELAY-BUDGET-01 live seam `execute_retry` 未消费 canonical typed budget/deadline: [\"tenant_pool.outbox_deadline_write(infra_tenant_scope(tenant),deadline\"]",
                    ),
                ],
            ),
            RelayBudgetRedCase::replace(
                "postgres DLX settlement deadline carrier",
                "adapters/postgres/src/outbox/settlement.rs",
                "tenant_pool\n        .outbox_deadline_write(",
                "pool\n        .deadline_global_transaction(",
                &[(
                    "adapters/postgres/src/outbox/settlement.rs",
                    "OUTBOX-RELAY-BUDGET-01 live seam `execute_dlx` 未消费 canonical typed budget/deadline: [\"outbox_deadline_write(infra_tenant_scope(tenant),deadline\"]",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres bundle carrier",
                "adapters/postgres/src/bundle.rs",
                "relay_budget: RelayBudget",
                "publish_timeout: Duration",
                &[(
                    "adapters/postgres/src/bundle.rs",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `relay_budget: RelayBudget`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "postgres migration carrier",
                "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
                "p_required_budget_ms >= p_lease_ttl_ms",
                "p_required_budget_ms > p_lease_ttl_ms",
                &[(
                    "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
                    "OUTBOX-RELAY-BUDGET-01 缺 canonical fragment `p_required_budget_ms >= p_lease_ttl_ms`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "audit required field",
                "adapters/amqp/src/publisher.rs",
                "publish_timeout_ms = self.publish_timeout.as_millis() as i64,",
                "deadline_ms = self.publish_timeout.as_millis() as i64,",
                &[(
                    "adapters/amqp/src/publisher.rs",
                    "审计事件 `amqp publish outcome is ambiguous` 缺安全字段 `publish_timeout_ms`",
                )],
            ),
            RelayBudgetRedCase::replace(
                "audit forbidden field",
                "adapters/amqp/src/publisher.rs",
                "delivery_outcome = \"unknown\",",
                "payload = ?request, delivery_outcome = \"unknown\",",
                &[(
                    "adapters/amqp/src/publisher.rs",
                    "审计事件 `amqp publish outcome is ambiguous` 泄漏禁止字段 `payload`",
                )],
            ),
            RelayBudgetRedCase::hardcode(
                "production hardcode",
                "assemblies/runtime/src/event_transport.rs",
                "fn parse_topology(s: &str) -> anyhow::Result<bootstrap::Topology> {",
                "\n    let _ = Duration::from_secs(40);",
                "生产 relay carrier 禁止固定 40/50/60 秒预算：`Duration::fromsecs(40)`",
            ),
            RelayBudgetRedCase::hardcode(
                "production relay const hardcode",
                "assemblies/runtime/src/event_transport.rs",
                "const RELAY_LEASE_TTL_ENV: &str = \"RSS_RELAY_LEASE_TTL_MS\";",
                "\nconst RELAY_BUDGET_HARDCODE: Duration = Duration::from_secs(40);",
                "生产 relay carrier 禁止固定 40/50/60 秒预算：`Duration::fromsecs(40)`",
            ),
        ];

        for case in &cases {
            assert_relay_budget_red_case(&sources, case);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relay_budget_guard_rejects_comment_test_string_and_audit_bait() {
        let root = workspace_root().expect("workspace root");
        let canonical = load_relay_budget_sources(&root).expect("relay budget sources");
        let cases = [
            (
                "rust comment bait",
                "assemblies/runtime/src/event_transport.rs",
                "relay: RelayTiming",
                "relay_budget_ms: u64, // relay: RelayTiming",
            ),
            (
                "rust cfg(test) bait",
                "adapters/amqp/src/publisher.rs",
                "validate_publish_timeout(publish_timeout)",
                "validate_publish_timeout(Duration::ZERO)",
            ),
            (
                "sql string bait",
                "adapters/postgres/migrations/0064_parameterize_outbox_relay_budget.sql",
                "p_required_budget_ms >= p_lease_ttl_ms",
                "p_required_budget_ms > p_lease_ttl_ms",
            ),
            (
                "audit cfg(test) bait",
                "adapters/amqp/src/publisher.rs",
                "amqp publish outcome is ambiguous",
                "amqp production timeout marker removed",
            ),
            (
                "runtime audit comment bait",
                "assemblies/runtime/src/phase/infra.rs",
                "runtime event transport budget loaded",
                "runtime event transport budget marker removed",
            ),
            (
                "runtime audit cfg(test) owner bait",
                "assemblies/runtime/src/phase/infra.rs",
                "runtime event transport budget loaded",
                "runtime event transport budget marker removed",
            ),
            (
                "runtime audit wrong owner bait",
                "assemblies/runtime/src/phase/infra.rs",
                "runtime event transport budget loaded",
                "runtime event transport budget marker removed",
            ),
        ];

        for (name, path, from, to) in cases {
            let mut sources = canonical.clone();
            let (_, content) = sources
                .iter_mut()
                .find(|(candidate, _)| candidate == Path::new(path))
                .expect("carrier");
            assert!(content.contains(from), "{name}: mutation anchor");
            *content = if name == "sql string bait" {
                content.replace(from, to)
            } else {
                content.replacen(from, to, 1)
            };
            match name {
                "rust cfg(test) bait" => content.push_str(
                    "\n#[cfg(test)] mod relay_budget_bait { fn bait(publish_timeout: std::time::Duration) { let _ = validate_publish_timeout(publish_timeout); } }\n",
                ),
                "sql string bait" => {
                    content.push_str("\nSELECT 'p_required_budget_ms >= p_lease_ttl_ms';\n")
                }
                "audit cfg(test) bait" => content.push_str(
                    r#"
#[cfg(test)]
mod relay_budget_audit_bait {
    fn bait() {
        tracing::warn!(
            phase = "confirm",
            publish_timeout_ms = 1,
            delivery_outcome = "unknown",
            broker_may_have_received = true,
            "amqp publish outcome is ambiguous"
        );
    }
}
"#,
                ),
                "runtime audit comment bait" => content.push_str(
                    "\n// tracing::info!(runtime.event_topology, relay.lease_ttl_ms, relay.publish_timeout_ms, relay.settle_timeout_ms, relay.safety_margin_ms, relay.required_budget_ms, \"runtime event transport budget loaded\");\n",
                ),
                "runtime audit cfg(test) owner bait" => content.push_str(
                    r#"
#[cfg(test)]
impl<'a> ProvidersBuilt<'a> {
    async fn build_infra(self) {
        tracing::info!(
            runtime.event_topology = "bait",
            relay.lease_ttl_ms = 1,
            relay.publish_timeout_ms = 1,
            relay.settle_timeout_ms = 1,
            relay.safety_margin_ms = 1,
            relay.required_budget_ms = 1,
            "runtime event transport budget loaded"
        );
    }
}
"#,
                ),
                "runtime audit wrong owner bait" => content.push_str(
                    r#"
impl<'a> OtherPhase<'a> {
    async fn build_infra(self) {
        tracing::info!(
            runtime.event_topology = "bait",
            relay.lease_ttl_ms = 1,
            relay.publish_timeout_ms = 1,
            relay.settle_timeout_ms = 1,
            relay.safety_margin_ms = 1,
            relay.required_budget_ms = 1,
            "runtime event transport budget loaded"
        );
    }
}
"#,
                ),
                _ => {}
            }
            assert!(
                !scan_relay_budget_sources(&sources).is_empty(),
                "{name} must not satisfy OUTBOX-RELAY-BUDGET-01"
            );
        }

        for (name, wrapper) in [
            ("runtime audit nested cfg(test) bait", "#[cfg(test)]"),
            ("runtime audit dead branch bait", "if false"),
        ] {
            let mut sources = canonical.clone();
            let (_, content) = sources
                .iter_mut()
                .find(|(candidate, _)| {
                    candidate == Path::new("assemblies/runtime/src/phase/infra.rs")
                })
                .expect("runtime infra carrier");
            *content = content.replacen(
                "runtime event transport budget loaded",
                "runtime event transport budget marker removed",
                1,
            );
            content.push_str(&format!(
                r#"
impl<'a> ProvidersBuilt<'a> {{
    async fn build_infra(self) {{
        {wrapper} {{
            tracing::info!(
                runtime.event_topology = "bait",
                relay.lease_ttl_ms = 1,
                relay.publish_timeout_ms = 1,
                relay.settle_timeout_ms = 1,
                relay.safety_margin_ms = 1,
                relay.required_budget_ms = 1,
                "runtime event transport budget loaded"
            );
        }}
    }}
}}
"#
            ));
            assert!(
                !scan_relay_budget_sources(&sources).is_empty(),
                "{name} must not satisfy OUTBOX-RELAY-BUDGET-01"
            );
        }
    }

    fn canonical_amqp_publisher_source() -> String {
        let root = workspace_root().expect("workspace root");
        std::fs::read_to_string(root.join("adapters/amqp/src/publisher.rs"))
            .expect("canonical adapters/amqp/src/publisher.rs")
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn amqp_publish_bypass_accepts_canonical_publisher() {
        let canonical = canonical_amqp_publisher_source();
        assert!(
            scan_amqp_publish_bypass(&canonical).is_empty(),
            "canonical Publisher::publish must pass AMQP-PUBLISH-BYPASS-01: {:#?}",
            scan_amqp_publish_bypass(&canonical)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn amqp_publish_bypass_synthetic_red_rejects_direct_bypasses() {
        let canonical = canonical_amqp_publisher_source();
        assert!(
            scan_amqp_publish_bypass(&canonical).is_empty(),
            "anti-vacuity baseline must be green before mutation"
        );

        let direct_error_cases = [
            (
                "PublisherError::transient",
                "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
                "return Err(PublisherError::transient(error));",
            ),
            (
                "PublisherError::permanent",
                "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
                "return Err(PublisherError::permanent(error));",
            ),
            (
                "PublisherError::ambiguous",
                "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
                "return Err(PublisherError::ambiguous(error));",
            ),
        ];
        for (name, from, to) in direct_error_cases {
            let mutated = canonical.replacen(from, to, 1);
            assert_ne!(mutated, canonical, "{name}: mutation anchor");
            assert!(
                !scan_amqp_publish_bypass(&mutated).is_empty(),
                "synthetic-red `{name}` must break AMQP-PUBLISH-BYPASS-01"
            );
        }

        let direct_retirement = canonical.replacen(
            "if let Err(source) = validate_transport_admission(",
            "self.retire_transport(snapshot.generation); if let Err(source) = validate_transport_admission(",
            1,
        );
        assert_ne!(
            direct_retirement, canonical,
            "retire_transport mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&direct_retirement).is_empty(),
            "direct retire_transport inside Publisher::publish must break AMQP-PUBLISH-BYPASS-01"
        );

        let try_bypass = canonical.replacen(
            "let snapshot = match self.transport_snapshot() {",
            "let _unchecked = validate_transport_admission(true, true)?; let snapshot = match self.transport_snapshot() {",
            1,
        );
        assert_ne!(try_bypass, canonical, "? mutation anchor");
        assert!(
            !scan_amqp_publish_bypass(&try_bypass).is_empty(),
            "outer `?` inside Publisher::publish must break AMQP-PUBLISH-BYPASS-01"
        );

        let macro_bypass = canonical.replacen(
            "if let Err(source) = validate_transport_admission(",
            r#"bypass_macro!(PublisherError::ambiguous("hidden")); if let Err(source) = validate_transport_admission("#,
            1,
        );
        assert_ne!(macro_bypass, canonical, "macro mutation anchor");
        assert!(
            !scan_amqp_publish_bypass(&macro_bypass).is_empty(),
            "macro-hidden PublisherError construction must break AMQP-PUBLISH-BYPASS-01"
        );

        let bare_macro_bypass = canonical.replacen(
            "if let Err(source) = validate_transport_admission(",
            r#"bypass_macro!(transient("hidden")); if let Err(source) = validate_transport_admission("#,
            1,
        );
        assert_ne!(
            bare_macro_bypass, canonical,
            "bare macro constructor mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&bare_macro_bypass).is_empty(),
            "bare macro `transient(...)` must break AMQP-PUBLISH-BYPASS-01"
        );

        let bare_import = canonical.replacen(
            "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
            "use PublisherError::transient; return Err(transient(error));",
            1,
        );
        assert_ne!(
            bare_import, canonical,
            "bare PublisherError constructor mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&bare_import).is_empty(),
            "bare `transient(...)` after use-import must break AMQP-PUBLISH-BYPASS-01"
        );

        let type_alias = canonical.replacen(
            "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
            "type PE = PublisherError; return Err(PE::permanent(error));",
            1,
        );
        assert_ne!(
            type_alias, canonical,
            "type-alias PublisherError constructor mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&type_alias).is_empty(),
            "`PE::permanent(...)` type-alias constructor must break AMQP-PUBLISH-BYPASS-01"
        );

        let async_error = canonical.replacen(
            "async {\n                let pending = transport",
            "async {\n                return Err(PublisherError::transient(\"async bypass\"));\n                let pending = transport",
            1,
        );
        assert_ne!(
            async_error, canonical,
            "async PublisherError mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&async_error).is_empty(),
            "direct PublisherError inside publish async block must break AMQP-PUBLISH-BYPASS-01"
        );

        let async_retire = canonical.replacen(
            "async {\n                let pending = transport",
            "async {\n                self.retire_transport(snapshot.generation);\n                let pending = transport",
            1,
        );
        assert_ne!(
            async_retire, canonical,
            "async retire_transport mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&async_retire).is_empty(),
            "direct retire_transport inside publish async block must break AMQP-PUBLISH-BYPASS-01"
        );

        let closure_error = canonical.replacen(
            "if let Err(source) = validate_transport_admission(",
            r#"let _bait = || PublisherError::ambiguous("closure"); if let Err(source) = validate_transport_admission("#,
            1,
        );
        assert_ne!(
            closure_error, canonical,
            "closure PublisherError mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&closure_error).is_empty(),
            "direct PublisherError inside publish closure must break AMQP-PUBLISH-BYPASS-01"
        );

        let reachable_local = canonical.replacen(
            "let inject_post_send_close = self.take_post_send_connection_close_fault();",
            r#"fn nested_live_failure(failure: PublishAttemptFailure) -> PublisherError {
                        PublisherError::transient(failure)
                    }
                    let _ = nested_live_failure;
                    let inject_post_send_close = self.take_post_send_connection_close_fault();"#,
            1,
        );
        assert_ne!(
            reachable_local, canonical,
            "reachable nested local function-item alias mutation anchor"
        );
        assert!(
            !scan_amqp_publish_bypass(&reachable_local).is_empty(),
            "reachable nested local function-item alias PublisherError constructor must break AMQP-PUBLISH-BYPASS-01"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn amqp_publish_bypass_does_not_lock_helper_pipeline_shape() {
        let canonical = canonical_amqp_publisher_source();

        let renamed_helper = canonical
            .replace("handle_publish_failure", "apply_publish_decision")
            .replace("run_publish_pipeline", "run_shared_deadline_pipeline");
        assert!(
            scan_amqp_publish_bypass(&renamed_helper).is_empty(),
            "helper/pipeline rename must not be a permanent AMQP-PUBLISH-BYPASS-01 shape lock: {:#?}",
            scan_amqp_publish_bypass(&renamed_helper)
        );

        let nested_and_dead = canonical.replacen(
            "impl Publisher for AmqpPublisher {",
            r#"fn dead_module_failure(failure: PublishAttemptFailure) -> PublisherError {
                PublisherError::ambiguous(failure)
            }
            impl AmqpPublisher {
                #[allow(dead_code)]
                fn dead_retire(&self, generation: u64) {
                    self.retire_transport(generation);
                }
            }
            impl Publisher for AmqpPublisher {"#,
            1,
        );
        let nested_and_dead = nested_and_dead.replacen(
            "let inject_post_send_close = self.take_post_send_connection_close_fault();",
            r#"fn nested_dead_failure(failure: PublishAttemptFailure) -> PublisherError {
                        PublisherError::transient(failure)
                    }
                    let inject_post_send_close = self.take_post_send_connection_close_fault();"#,
            1,
        );
        assert!(
            scan_amqp_publish_bypass(&nested_and_dead).is_empty(),
            "uncalled nested/dead helpers must stay green for AMQP-PUBLISH-BYPASS-01: {:#?}",
            scan_amqp_publish_bypass(&nested_and_dead)
        );

        let reordered = canonical.replacen(
            "let event_id = request.event_id().as_str().to_string();\n        let topic = request.topic().as_str().to_string();\n        let properties = build_properties(&event_id, request.metadata());",
            "let topic = request.topic().as_str().to_string();\n        let event_id = request.event_id().as_str().to_string();\n        let properties = build_properties(&event_id, request.metadata());",
            1,
        );
        assert_ne!(reordered, canonical, "local order mutation anchor");
        assert!(
            scan_amqp_publish_bypass(&reordered).is_empty(),
            "local call order must not be a permanent AMQP-PUBLISH-BYPASS-01 shape lock: {:#?}",
            scan_amqp_publish_bypass(&reordered)
        );

        let no_tail_ok = canonical.replacen(
            "        if confirmation.take_message().is_some() {\n            return Err(self.handle_publish_failure(PublishRejected::Unroutable.into()));\n        }\n        Ok(())\n    }",
            "        if confirmation.take_message().is_some() {\n            return Err(self.handle_publish_failure(PublishRejected::Unroutable.into()));\n        }\n        return Ok(());\n    }",
            1,
        );
        assert_ne!(no_tail_ok, canonical, "tail Ok(()) mutation anchor");
        assert!(
            scan_amqp_publish_bypass(&no_tail_ok).is_empty(),
            "trailing Ok(()) must not be a permanent AMQP-PUBLISH-BYPASS-01 shape lock: {:#?}",
            scan_amqp_publish_bypass(&no_tail_ok)
        );

        // Intentional non-coverage: reviewer-style sibling `self.evil()` that constructs Ambiguous
        // without retire stays green. BYPASS only owns direct lexical publish surface; Ambiguous⇒
        // retire/fencing is enrolled AMQP ambiguity T2 (post-send close) + Hard decision types.
        // Restoring the retired funnel/sibling body scanner is forbidden (#1987).
        let sibling_evil = canonical.replacen(
            "fn retire_transport(&self, generation: u64) {",
            r#"fn sibling_ambiguous_without_retire(&self, failure: PublisherTransportError) -> PublisherError {
                PublisherError::ambiguous(failure)
            }
            fn retire_transport(&self, generation: u64) {"#,
            1,
        );
        let sibling_evil = sibling_evil.replacen(
            "return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));",
            "return Err(self.sibling_ambiguous_without_retire(error));",
            1,
        );
        assert_ne!(
            sibling_evil, canonical,
            "sibling Ambiguous-without-retire mutation anchor"
        );
        assert!(
            scan_amqp_publish_bypass(&sibling_evil).is_empty(),
            "AmqpPublisher sibling method bodies must stay outside AMQP-PUBLISH-BYPASS-01: {:#?}",
            scan_amqp_publish_bypass(&sibling_evil)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relay_budget_audit_accepts_amqp_ambiguous_helper_rename() {
        let root = workspace_root().expect("workspace root");
        let mut sources = load_relay_budget_sources(&root).expect("relay budget sources");
        let (_, content) = sources
            .iter_mut()
            .find(|(candidate, _)| candidate == Path::new("adapters/amqp/src/publisher.rs"))
            .expect("amqp publisher carrier");
        let renamed = content.replace("handle_publish_failure", "apply_publish_decision");
        assert_ne!(
            renamed.as_str(),
            content.as_str(),
            "amqp ambiguous audit helper rename mutation anchor"
        );
        *content = renamed;
        let findings = scan_relay_budget_sources(&sources);
        assert!(
            findings.is_empty(),
            "OUTBOX-RELAY-BUDGET-01 AMQP ambiguous audit must locate by tracing marker, not helper ident: {findings:#?}"
        );
    }

    fn amqp_connection_guard_fixture() -> &'static str {
        r#"
            pub(crate) async fn connect(
                endpoint: &AmqpEndpoint,
                name: &str,
                confirm: bool,
            ) -> Result<Connection, Error> {
                connect_with_context(endpoint, name, confirm, ConnectContext::Initial).await
            }

            pub(crate) async fn connect_with_private_ca(
                endpoint: &AmqpEndpoint,
                name: &str,
                confirm: bool,
                ca: &AmqpPrivateCa,
            ) -> Result<Connection, Error> {
                connect_with_context(endpoint, name, confirm, ConnectContext::Initial).await
            }

            pub(crate) async fn reconnect_publisher(
                endpoint: &AmqpEndpoint,
                name: &str,
                generation: u64,
            ) -> Result<Connection, Error> {
                connect_with_context(
                    endpoint,
                    name,
                    true,
                    ConnectContext::Recovery { replacement_generation: generation + 1 },
                ).await
            }

            async fn connect_with_context(
                endpoint: &AmqpEndpoint,
                name: &str,
                confirm: bool,
                context: ConnectContext,
            ) -> Result<Connection, Error> {
                let url = endpoint.expose();
                let connection = Connection::connect(url, ConnectionProperties::default()).await?;
                Ok(connection)
            }

            async fn connect_with_exclusive_private_ca(
                url: &str,
                ca: &AmqpPrivateCa,
            ) -> Result<Connection, Error> {
                Connection::connector(
                    uri,
                    runtime,
                    connector,
                    ConnectionProperties::default(),
                ).await
            }
        "#
    }

    #[test]
    fn relay_budget_guard_accepts_amqp_connection_recovery_owner() -> Result<()> {
        let root = workspace_root()?;
        let content = std::fs::read_to_string(root.join("adapters/amqp/src/conn.rs"))?;
        assert!(
            scan_amqp_connection_recovery_owner(&content).is_empty(),
            "canonical conn.rs must retain one RSS-owned recovery path"
        );

        let cfg_test_bait = amqp_connection_guard_fixture().to_string()
            + r#"
                #[cfg(test)]
                fn lapin_auto_recovery_bait() {
                    let _ = ConnectionProperties::default().enable_auto_recover(3);
                }
            "#;
        assert!(
            scan_amqp_connection_recovery_owner(&cfg_test_bait).is_empty(),
            "cfg(test) declarations must not become production recovery owners"
        );

        let nested_declaration_bait = amqp_connection_guard_fixture().replacen(
            "let url = endpoint.expose();",
            r#"
                fn nested_bait(url: &str) {
                    let _ = Connection::connect(
                        url,
                        ConnectionProperties::default().enable_auto_recover(3),
                    );
                }
                let url = endpoint.expose();"#,
            1,
        );
        assert!(
            scan_amqp_connection_recovery_owner(&nested_declaration_bait).is_empty(),
            "an uncalled nested declaration must not be counted as a production owner"
        );

        let sibling_scope_same_names = amqp_connection_guard_fixture().replacen(
            "let url = endpoint.expose();",
            r#"{
                    fn scoped_helper() {}
                    scoped_helper();
                }
                {
                    fn scoped_helper() {}
                    let call = scoped_helper;
                    call();
                }
                let url = endpoint.expose();"#,
            1,
        );
        assert!(
            scan_amqp_connection_recovery_owner(&sibling_scope_same_names).is_empty(),
            "same-named connection helpers in distinct lexical scopes must not collide"
        );
        Ok(())
    }

    #[test]
    fn relay_budget_guard_rejects_amqp_connection_auto_recovery_mutations() {
        let canonical = amqp_connection_guard_fixture();
        let mutations = [
            (
                "lapin auto-recovery",
                canonical.replacen(
                    "ConnectionProperties::default()",
                    "ConnectionProperties::default().enable_auto_recover(3)",
                    1,
                ),
            ),
            (
                "non-canonical properties helper",
                canonical.replacen(
                    "ConnectionProperties::default()",
                    "publisher_connection_properties()",
                    1,
                ),
            ),
            (
                "second connection owner",
                canonical.to_string()
                    + r#"
                        async fn lapin_recovery_owner(url: &str) {
                            let _ = Connection::connect(
                                url,
                                ConnectionProperties::default(),
                            ).await;
                        }
                    "#,
            ),
            (
                "nested connection owner",
                canonical.replacen(
                    "let connection = Connection::connect(url, ConnectionProperties::default()).await?;",
                    "let make_connection = || async { Connection::connect(url, ConnectionProperties::default()).await }; let connection = make_connection().await?;",
                    1,
                ),
            ),
            (
                "called block-local auto-recovery owner",
                canonical.replacen(
                    "let url = endpoint.expose();",
                    r#"let url = endpoint.expose();
                        fn nested_recovery_owner(url: &str) {
                            let _ = Connection::connect(
                                url,
                                ConnectionProperties::default().enable_auto_recover(3),
                            );
                        }
                        nested_recovery_owner(url);"#,
                    1,
                ),
            ),
            (
                "inner block aliased auto-recovery owner",
                canonical.replacen(
                    "let url = endpoint.expose();",
                    r#"let url = endpoint.expose();
                        {
                            fn nested_recovery_owner(url: &str) {
                                let _ = Connection::connect(
                                    url,
                                    ConnectionProperties::default().enable_auto_recover(3),
                                );
                            }
                            let recover = nested_recovery_owner;
                            recover(url);
                        }"#,
                    1,
                ),
            ),
            (
                "if branch local connection owner",
                canonical.replacen(
                    "let url = endpoint.expose();",
                    r#"let url = endpoint.expose();
                        if !url.is_empty() {
                            fn nested_recovery_owner(url: &str) {
                                let _ = Connection::connect(
                                    url,
                                    ConnectionProperties::default().enable_auto_recover(3),
                                );
                            }
                            nested_recovery_owner(url);
                        }"#,
                    1,
                ),
            ),
            (
                "match arm local connection owner",
                canonical.replacen(
                    "let url = endpoint.expose();",
                    r#"let url = endpoint.expose();
                        match url.is_empty() {
                            false => {
                                fn nested_recovery_owner(url: &str) {
                                    let _ = Connection::connect(
                                        url,
                                        ConnectionProperties::default().enable_auto_recover(3),
                                    );
                                }
                                nested_recovery_owner(url);
                            }
                            true => {}
                        }"#,
                    1,
                ),
            ),
            (
                "ambiguous local recovery owner provenance",
                canonical.replacen(
                    "let url = endpoint.expose();",
                    r#"fn duplicate_owner(_: &str) {}
                        fn duplicate_owner(_: &str) {}
                        let unresolved = duplicate_owner;
                        unresolved(endpoint.expose());
                        let url = endpoint.expose();"#,
                    1,
                ),
            ),
            (
                "recovery context removed",
                canonical.replacen(
                    "ConnectContext::Recovery { replacement_generation: generation + 1 }",
                    "ConnectContext::Initial",
                    1,
                ),
            ),
        ];
        for (name, mutation) in mutations {
            assert!(
                !scan_amqp_connection_recovery_owner(&mutation).is_empty(),
                "synthetic-red `{name}` must break AMQP-RSS-RECOVERY-OWNER-01"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn relay_budget_guard_rejects_live_seam_drift_with_production_dead_helper_bait() {
        let root = workspace_root().expect("workspace root");
        let canonical = load_relay_budget_sources(&root).expect("relay budget sources");
        let cases = [
            (
                "runtime gate",
                "assemblies/runtime/src/event_transport.rs",
                "pg.validate_relay_budget(timing.budget)",
                "pg.validate_relay_budget(relay_budget_dead_value())",
                "\n#[allow(dead_code)] fn dead(pg: &PgRuntimeHandle, timing: RelayTiming) { let _ = pg.validate_relay_budget(timing.budget); }\n",
                "wire_event_transport",
            ),
            (
                "postgres watchdog",
                "adapters/postgres/src/outbox.rs",
                "with_publisher_watchdog(deadline, self.relay_budget",
                "with_publisher_watchdog(deadline, relay_budget_dead_value()",
                "\nimpl PgOutbox { #[allow(dead_code)] async fn dead(&self, deadline: tokio::time::Instant, request: PublishRequest) { let _ = with_publisher_watchdog(deadline, self.relay_budget, self.publisher.publish(request)).await; } }\n",
                "publish_claimed_before",
            ),
            (
                "postgres settle retry",
                "adapters/postgres/src/outbox.rs",
                "settlement::retry(&self.tenant_pool, claimed, self.relay_budget)",
                "settlement::retry(&self.tenant_pool, claimed, relay_budget_dead_value())",
                "\nimpl PgOutbox { #[allow(dead_code)] async fn dead_settle(&self, claimed: &PgClaimedOutboxEntry) { let _ = settlement::retry(&self.tenant_pool, claimed, self.relay_budget).await; } }\n",
                "settle_publish_failure",
            ),
        ];

        for (name, path, from, to, bait, owner) in cases {
            let mut sources = canonical.clone();
            let (_, content) = sources
                .iter_mut()
                .find(|(candidate, _)| candidate == Path::new(path))
                .expect("relay carrier");
            assert!(content.contains(from), "{name}: mutation anchor");
            *content = content.replacen(from, to, 1);
            content.push_str(bait);
            let findings = scan_relay_budget_sources(&sources);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains(owner)),
                "{name}: dead helper must not satisfy live owner: {findings:#?}"
            );
        }
    }
}
