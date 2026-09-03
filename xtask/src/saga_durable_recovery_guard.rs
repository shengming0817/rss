//! Saga durable-recovery production-flow guard.
//!
//! The workspace binding and fixture parser share one proof path. The parser follows
//! production-reachable wrappers along branch-sensitive control-flow paths, ignores
//! comments/strings/test-only items, rejects legacy topology identifiers anywhere in production,
//! fails closed on effect-bearing closure/inline-async bodies, and inspects every `Unknown` match
//! arm path for direct or wrapped retry calls.
//!
//! INVARIANT: SAGA-DURABLE-RECOVERY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::synthetic_red_rejects_mutually_unreachable_event_fragments", anti_vacuity = "tests::workspace_saga_recovery_flow_is_live" } -- the real Saga executor must expose a production-reachable intent -> permit -> effect -> completion flow, must never route a typed unknown outcome into retry, must keep the post-#1926 single-store SagaCapabilityRequirement closed set, and must pin definition identity via advance_registered + definition-free SagaStartRequest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{Attribute, Block, Expr, ImplItem, Item, ItemFn, ItemImpl, ItemMod, Pat, TraitItem};

use crate::diagnostic::{Finding, GovernanceCheck, finding};

const CANONICAL_EXECUTOR: &str = "crates/eventexec/src/saga.rs";
const SAGA_CAPABILITY_SCHEMA: &str = "crates/assembly-schema/src/lib.rs";
const CLOSED_SAGA_CAPABILITIES: &[&str] = &[
    "TypedActions",
    "DefinitionRegistry",
    "DurableStore",
    "Hydrator",
    "EffectProbe",
    "DeadLetterStore",
    "Worker",
    "Readiness",
];
const LEGACY_PORT_FILES: &[&str] = &[
    "crates/diport/src/saga_instance_store.rs",
    "crates/diport/src/saga_journal.rs",
    "crates/diport/src/saga_receipt_store.rs",
];
const GLOBAL_LEGACY_IDENTS: &[&str] = &[
    "SagaInstanceStore",
    "DynSagaInstanceStore",
    "SagaJournal",
    "DynSagaJournal",
    "SagaReceiptStore",
    "DynSagaReceiptStore",
    "SagaRuntimeLock",
    "SagaJournalAppendOutcome",
    "SagaJournalAppendRecord",
    "RuntimeLockUnavailable",
    "RuntimeLockLost",
    "RuntimeLockRenewUnknown",
    "saga_checkpoint_id",
];
const EXECUTOR_LEGACY_IDENTS: &[&str] = &[
    "SagaInstanceStore",
    "DynSagaInstanceStore",
    "SagaJournal",
    "DynSagaJournal",
    "SagaReceiptStore",
    "DynSagaReceiptStore",
    "SagaRuntimeLock",
    "SagaJournalAppendOutcome",
    "SagaJournalAppendRecord",
    "RuntimeLockUnavailable",
    "RuntimeLockLost",
    "RuntimeLockRenewUnknown",
    "OwnerCheckpointStore",
    "saga_checkpoint_id",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    LiveEffectOrder,
    UnknownNeverRetries,
    LegacyTopologyAbsent,
}

pub(crate) struct SagaDurableRecoveryGuard;

impl GovernanceCheck for SagaDurableRecoveryGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "saga-durable-recovery-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = crate::workspace_root()?;
        let executor_path = root.join(CANONICAL_EXECUTOR);
        let executor = std::fs::read_to_string(&executor_path)
            .with_context(|| format!("read {}", executor_path.display()))?;
        let executor_source = [(Path::new(CANONICAL_EXECUTOR), executor.as_str())];

        let mut findings = analyze_sources(&executor_source, forward_symbols())?;
        findings.extend(analyze_sources(&executor_source, compensation_symbols())?);
        if !executor_impl_has_durable_store(&executor)? {
            findings.push(finding(
                Rule::LegacyTopologyAbsent,
                CANONICAL_EXECUTOR,
                "the ExecCtx impl owning both live entries must be directly bounded by SagaDurableStore",
            ));
        }
        if !executor_has_pinned_definition_boundary(&executor)? {
            findings.push(finding(
                Rule::LegacyTopologyAbsent,
                CANONICAL_EXECUTOR,
                "SagaExecutor::advance_registered must take SagaInstanceRef plus listing-pinned SagaDefinitionIdentity; SagaStartRequest must not carry caller-chosen definition",
            ));
        }
        let production_sources = production_sources(&root)?;
        findings.extend(scan_legacy_sources(
            &production_sources,
            GLOBAL_LEGACY_IDENTS,
        )?);
        let capability_source = std::fs::read_to_string(root.join(SAGA_CAPABILITY_SCHEMA))
            .with_context(|| format!("read {SAGA_CAPABILITY_SCHEMA}"))?;
        if let Some(detail) = saga_capability_schema_drift(&capability_source)? {
            findings.push(finding(
                Rule::LegacyTopologyAbsent,
                SAGA_CAPABILITY_SCHEMA,
                detail,
            ));
        }
        for legacy in LEGACY_PORT_FILES {
            if root.join(legacy).exists() {
                findings.push(finding(
                    Rule::LegacyTopologyAbsent,
                    *legacy,
                    "legacy split Saga port file still exists",
                ));
            }
        }
        findings.sort_by(|left, right| {
            (&left.subject, left.rule, &left.detail).cmp(&(
                &right.subject,
                right.rule,
                &right.detail,
            ))
        });
        findings.dedup();
        Ok((
            format!(
                "2 live Saga effect flows and {} production Rust sources checked; single SagaDurableStore topology enforced",
                production_sources.len()
            ),
            findings,
        ))
    }
}

fn executor_has_pinned_definition_boundary(source: &str) -> Result<bool> {
    let file = syn::parse_file(source)
        .context("saga-durable-recovery: parse canonical executor definition boundary")?;
    let advance_ok = file.items.iter().any(|item| {
        let Item::Trait(item_trait) = item else {
            return false;
        };
        if item_trait.ident != "SagaExecutor" {
            return false;
        }
        item_trait.items.iter().any(|item| {
            let TraitItem::Fn(method) = item else {
                return false;
            };
            // self + instance + listed_definition
            if method.sig.ident != "advance_registered" || method.sig.inputs.len() != 3 {
                return false;
            }
            let Some(syn::FnArg::Typed(instance)) = method.sig.inputs.iter().nth(1) else {
                return false;
            };
            let Some(syn::FnArg::Typed(listed)) = method.sig.inputs.iter().nth(2) else {
                return false;
            };
            matches!(instance.pat.as_ref(), Pat::Ident(ident) if ident.ident == "instance")
                && type_tail(&instance.ty).as_deref() == Some("SagaInstanceRef")
                && matches!(listed.pat.as_ref(), Pat::Ident(ident) if ident.ident == "listed_definition")
                && type_tail(&listed.ty).as_deref() == Some("SagaDefinitionIdentity")
        })
    });
    let start_request_ok = file.items.iter().any(|item| {
        let Item::Struct(item_struct) = item else {
            return false;
        };
        if item_struct.ident != "SagaStartRequest" {
            return false;
        }
        let fields: Vec<_> = item_struct
            .fields
            .iter()
            .filter_map(|field| {
                let name = field.ident.as_ref()?.to_string();
                let ty = type_tail(&field.ty)?;
                Some((name, ty))
            })
            .collect();
        fields == [("instance".to_owned(), "SagaInstanceRef".to_owned())]
    });
    Ok(advance_ok && start_request_ok)
}

fn saga_capability_schema_drift(source: &str) -> Result<Option<String>> {
    let file =
        syn::parse_file(source).context("saga-durable-recovery: parse Saga capability schema")?;
    let Some(item) = file.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "SagaCapabilityRequirement" => Some(item),
        _ => None,
    }) else {
        return Ok(Some(
            "closed SagaCapabilityRequirement enum is missing".to_owned(),
        ));
    };
    let actual = item
        .variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect::<Vec<_>>();
    let expected = CLOSED_SAGA_CAPABILITIES
        .iter()
        .map(|variant| (*variant).to_owned())
        .collect::<Vec<_>>();
    if actual == expected {
        Ok(None)
    } else {
        Ok(Some(format!(
            "Saga capability schema must be the single-store closed set {expected:?}, got {actual:?}"
        )))
    }
}

fn executor_impl_has_durable_store(source: &str) -> Result<bool> {
    let file =
        syn::parse_file(source).context("saga-durable-recovery: parse canonical executor")?;
    Ok(file.items.iter().any(|item| {
        let Item::Impl(item_impl) = item else {
            return false;
        };
        if type_tail(&item_impl.self_ty).as_deref() != Some("ExecCtx") {
            return false;
        }
        let methods = item_impl
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) => Some(method.sig.ident.to_string()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        methods.contains("run_forward_step")
            && methods.contains("compensate_step")
            && compact_tokens(item_impl).contains("SagaDurableStore")
    }))
}

fn forward_symbols() -> RecoverySymbols<'static> {
    RecoverySymbols {
        entry: "ExecCtx::run_forward_step",
        intent_calls: FORWARD_INTENT,
        permit_calls: FORWARD_PERMIT,
        effect_calls: FORWARD_EFFECT,
        completion_calls: FORWARD_COMPLETION,
        completion_commit: Some(CompletionCommitSpec {
            owner: "ExecCtx::commit_forward_completion",
            constructor: "ForwardCompleted",
        }),
        unknown_patterns: FORWARD_UNKNOWN,
        unknown_terminal_calls: FORWARD_OPERATOR,
        retry_calls: RETRY_CALLS,
        legacy_idents: EXECUTOR_LEGACY_IDENTS,
    }
}

fn compensation_symbols() -> RecoverySymbols<'static> {
    RecoverySymbols {
        entry: "ExecCtx::compensate_step",
        intent_calls: COMPENSATION_INTENT,
        permit_calls: COMPENSATION_PERMIT,
        effect_calls: COMPENSATION_EFFECT,
        completion_calls: COMPENSATION_COMPLETION,
        completion_commit: Some(CompletionCommitSpec {
            owner: "ExecCtx::finish_compensation_success",
            constructor: "CompensationCompleted",
        }),
        unknown_patterns: COMPENSATION_UNKNOWN,
        unknown_terminal_calls: COMPENSATION_OPERATOR,
        retry_calls: RETRY_CALLS,
        legacy_idents: EXECUTOR_LEGACY_IDENTS,
    }
}

#[derive(Debug, Clone, Copy)]
struct RecoverySymbols<'a> {
    entry: &'a str,
    intent_calls: &'a [CallAnchor<'a>],
    permit_calls: &'a [CallAnchor<'a>],
    effect_calls: &'a [CallAnchor<'a>],
    completion_calls: &'a [CallAnchor<'a>],
    completion_commit: Option<CompletionCommitSpec<'a>>,
    unknown_patterns: &'a [&'a str],
    unknown_terminal_calls: &'a [CallAnchor<'a>],
    retry_calls: &'a [&'a str],
    legacy_idents: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
struct CompletionCommitSpec<'a> {
    owner: &'a str,
    constructor: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct CallAnchor<'a> {
    name: &'a str,
    shape_marker: Option<&'a str>,
}

impl<'a> CallAnchor<'a> {
    const fn named(name: &'a str) -> Self {
        Self {
            name,
            shape_marker: None,
        }
    }

    const fn marked(name: &'a str, shape_marker: &'a str) -> Self {
        Self {
            name,
            shape_marker: Some(shape_marker),
        }
    }

    fn matches(self, call: &Call) -> bool {
        call.name == self.name
            && self
                .shape_marker
                .is_none_or(|marker| call.shape.contains(marker))
    }
}

const FORWARD_INTENT: &[CallAnchor<'static>] = &[CallAnchor::marked(
    "mutate",
    "SagaDurableMutation::ForwardIntent",
)];
const FORWARD_PERMIT: &[CallAnchor<'static>] =
    &[CallAnchor::marked("and_then", "SagaForwardPermit::new")];
const FORWARD_EFFECT: &[CallAnchor<'static>] = &[CallAnchor::named("do_it")];
const FORWARD_COMPLETION: &[CallAnchor<'static>] = &[CallAnchor::named("ForwardCompleted")];
const FORWARD_UNKNOWN: &[&str] = &["SagaProbeOutcome::Unknown"];
const FORWARD_OPERATOR: &[CallAnchor<'static>] = &[CallAnchor::marked(
    "require_operator",
    "SagaOperatorReason::ForwardOutcomeUnknown",
)];
const COMPENSATION_INTENT: &[CallAnchor<'static>] = &[CallAnchor::marked(
    "mutate",
    "SagaDurableMutation::CompensationIntent",
)];
const COMPENSATION_PERMIT: &[CallAnchor<'static>] = &[CallAnchor::marked(
    "and_then",
    "SagaCompensationPermit::new",
)];
const COMPENSATION_EFFECT: &[CallAnchor<'static>] = &[CallAnchor::named("undo_it")];
const COMPENSATION_COMPLETION: &[CallAnchor<'static>] =
    &[CallAnchor::named("CompensationCompleted")];
const COMPENSATION_UNKNOWN: &[&str] = &["SagaProbeOutcome::Unknown"];
const COMPENSATION_OPERATOR: &[CallAnchor<'static>] = &[CallAnchor::marked(
    "require_operator",
    "SagaOperatorReason::CompensationOutcomeUnknown",
)];
const RETRY_CALLS: &[&str] = &["sleep"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CallKind {
    Function,
    SelfMethod,
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Call {
    kind: CallKind,
    name: String,
    shape: String,
    site: Option<usize>,
}

impl Call {
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
struct FunctionNode {
    key: String,
    owner: Option<String>,
    calls: Vec<Call>,
    call_paths: Vec<Vec<Call>>,
    opaque_regions: Vec<OpaqueRegion>,
    path_overflowed: bool,
    unknown_arm_paths: Vec<Vec<Vec<Call>>>,
}

#[derive(Debug, Clone)]
struct OpaqueRegion {
    kind: &'static str,
    calls: Vec<Call>,
}

#[derive(Default)]
struct Program {
    nodes: BTreeMap<String, FunctionNode>,
    by_name: BTreeMap<String, Vec<String>>,
    legacy_hits: Vec<(String, String)>,
}

fn production_sources(root: &Path) -> Result<Vec<(std::path::PathBuf, String)>> {
    let mut paths = Vec::new();
    for source_root in ["crates", "adapters"] {
        paths.extend(crate::src_scan::rs_files(&root.join(source_root))?);
    }
    paths.sort();
    paths.dedup();
    paths.retain(|path| {
        let file = path.file_name().and_then(|name| name.to_str());
        file != Some("tests.rs")
            && !crate::src_scan::is_crate_internal_integration_test_source(path)
            && !path
                .components()
                .any(|component| component.as_os_str() == "tests")
    });
    if paths.is_empty() {
        bail!("saga-durable-recovery: production Rust source universe is empty");
    }
    paths
        .into_iter()
        .map(|path| {
            let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            Ok((relative, source))
        })
        .collect()
}

fn scan_legacy_sources(
    sources: &[(std::path::PathBuf, String)],
    legacy_idents: &[&str],
) -> Result<Vec<Finding<Rule>>> {
    let mut program = Program::default();
    for (path, source) in sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("saga-durable-recovery: parse {}", path.display()))?;
        for item in &file.items {
            if !item_is_test_only(item) {
                collect_legacy_hits(&mut program, path, item, legacy_idents);
            }
        }
    }
    Ok(program
        .legacy_hits
        .into_iter()
        .map(|(path, ident)| {
            finding(
                Rule::LegacyTopologyAbsent,
                path,
                format!("legacy Saga topology identifier `{ident}` remains in production AST"),
            )
        })
        .collect())
}

fn analyze_sources(
    sources: &[(&Path, &str)],
    symbols: RecoverySymbols<'_>,
) -> Result<Vec<Finding<Rule>>> {
    let mut program = Program::default();
    let mut parsed_sources = Vec::new();
    for (path, source) in sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("saga-durable-recovery: parse {}", path.display()))?;
        parsed_sources.push((*path, file));
    }
    let mut declared_names = BTreeSet::new();
    for (_, file) in &parsed_sources {
        collect_declared_names(&file.items, &mut declared_names);
    }
    for (path, file) in &parsed_sources {
        collect_items(
            &mut program,
            path,
            &file.items,
            &mut Vec::new(),
            &symbols,
            &declared_names,
        );
    }

    let mut findings = program
        .legacy_hits
        .iter()
        .map(|(path, ident)| {
            finding(
                Rule::LegacyTopologyAbsent,
                path,
                format!("legacy Saga topology identifier `{ident}` remains in production AST"),
            )
        })
        .collect::<Vec<_>>();

    let Some(entry) = program.nodes.get(symbols.entry) else {
        findings.push(finding(
            Rule::LiveEffectOrder,
            symbols.entry,
            "canonical production executor entry is missing; helper, string, or test-only bait cannot satisfy the gate",
        ));
        return Ok(findings);
    };

    let mut reachable = BTreeSet::new();
    collect_reachable(&program, entry, &mut reachable, &mut BTreeSet::new());
    let event_paths = expand_event_paths(
        &program,
        entry,
        symbols,
        &mut BTreeSet::new(),
        &mut BTreeMap::new(),
    );
    findings.extend(validate_event_paths(symbols.entry, &event_paths));
    for key in &reachable {
        let node = &program.nodes[key];
        if node.path_overflowed {
            findings.push(finding(
                Rule::LiveEffectOrder,
                &node.key,
                "control-flow path expansion exceeded the fail-closed analysis bound",
            ));
        }
        for region in &node.opaque_regions {
            if calls_reach_anchors(
                &program,
                node,
                &region.calls,
                symbols.effect_calls,
                &mut BTreeSet::new(),
            ) {
                findings.push(finding(
                    Rule::LiveEffectOrder,
                    &node.key,
                    format!(
                        "effect-bearing {} body is not executed in a statically provable path; move the effect into the ordinary intent -> permit -> effect -> completion flow",
                        region.kind
                    ),
                ));
            }
        }
    }
    if let Some(commit) = symbols.completion_commit
        && !completion_reaches_store_mutation(&program, commit)
    {
        findings.push(finding(
            Rule::LiveEffectOrder,
            commit.owner,
            "typed completion construction must flow into a direct SagaDurableStore::mutate call in the same reachable helper",
        ));
    }

    for key in &reachable {
        let node = &program.nodes[key];
        for arm_paths in &node.unknown_arm_paths {
            for arm_path in arm_paths {
                let reaches_operator = calls_reach_anchors(
                    &program,
                    node,
                    arm_path,
                    symbols.unknown_terminal_calls,
                    &mut BTreeSet::new(),
                );
                let reaches_retry = calls_reach_named(
                    &program,
                    node,
                    arm_path,
                    symbols.retry_calls,
                    &mut BTreeSet::new(),
                );
                if !reaches_operator || reaches_retry {
                    findings.push(finding(
                        Rule::UnknownNeverRetries,
                        &node.key,
                        "every typed Unknown control-flow path must reach the operator-required transition and no retry, directly or through a production wrapper",
                    ));
                }
            }
        }
    }

    findings.sort_by(|left, right| {
        (&left.subject, left.rule, &left.detail).cmp(&(&right.subject, right.rule, &right.detail))
    });
    findings.dedup();
    Ok(findings)
}

fn completion_reaches_store_mutation(program: &Program, spec: CompletionCommitSpec<'_>) -> bool {
    let Some(node) = program.nodes.get(spec.owner) else {
        return false;
    };
    let constructor_paths = node
        .call_paths
        .iter()
        .filter(|path| path.iter().any(|call| call.name() == spec.constructor))
        .collect::<Vec<_>>();
    !constructor_paths.is_empty()
        && constructor_paths.iter().all(|path| {
            let constructor = path.iter().position(|call| call.name() == spec.constructor);
            let mutation = path.iter().position(|call| {
                call.name() == "mutate" && call.shape.contains("self.store.mutate")
            });
            matches!((constructor, mutation), (Some(left), Some(right)) if left < right)
        })
}

fn collect_items(
    program: &mut Program,
    path: &Path,
    items: &[Item],
    modules: &mut Vec<String>,
    symbols: &RecoverySymbols<'_>,
    declared_names: &BTreeSet<String>,
) {
    for item in items {
        if item_is_test_only(item) {
            continue;
        }
        collect_legacy_hits(program, path, item, symbols.legacy_idents);
        match item {
            Item::Fn(item_fn) => {
                collect_function(program, modules, None, item_fn, symbols, declared_names)
            }
            Item::Impl(item_impl) => {
                collect_impl(program, modules, item_impl, symbols, declared_names);
            }
            Item::Mod(item_mod) => {
                collect_module(program, path, modules, item_mod, symbols, declared_names)
            }
            _ => {}
        }
    }
}

fn collect_declared_names(items: &[Item], names: &mut BTreeSet<String>) {
    for item in items {
        if item_is_test_only(item) {
            continue;
        }
        match item {
            Item::Fn(item_fn) => {
                names.insert(item_fn.sig.ident.to_string());
            }
            Item::Impl(item_impl) => {
                for item in &item_impl.items {
                    if let ImplItem::Fn(method) = item
                        && !attrs_are_test_only(&method.attrs)
                    {
                        names.insert(method.sig.ident.to_string());
                    }
                }
            }
            Item::Mod(item_mod) => {
                if let Some((_, items)) = &item_mod.content {
                    collect_declared_names(items, names);
                }
            }
            _ => {}
        }
    }
}

fn collect_module(
    program: &mut Program,
    path: &Path,
    modules: &mut Vec<String>,
    item_mod: &ItemMod,
    symbols: &RecoverySymbols<'_>,
    declared_names: &BTreeSet<String>,
) {
    let Some((_, items)) = &item_mod.content else {
        return;
    };
    modules.push(item_mod.ident.to_string());
    collect_items(program, path, items, modules, symbols, declared_names);
    modules.pop();
}

fn collect_impl(
    program: &mut Program,
    modules: &[String],
    item_impl: &ItemImpl,
    symbols: &RecoverySymbols<'_>,
    declared_names: &BTreeSet<String>,
) {
    let owner = type_tail(&item_impl.self_ty);
    for impl_item in &item_impl.items {
        let ImplItem::Fn(method) = impl_item else {
            continue;
        };
        if attrs_are_test_only(&method.attrs) {
            continue;
        }
        let Some(owner) = owner.as_deref() else {
            continue;
        };
        let key = qualified_key(modules, Some(owner), &method.sig.ident.to_string());
        insert_node(
            program,
            FunctionNode::from_block(
                key,
                Some(owner.to_owned()),
                &method.block,
                symbols.unknown_patterns,
                *symbols,
                declared_names,
            ),
        );
    }
}

fn collect_function(
    program: &mut Program,
    modules: &[String],
    owner: Option<&str>,
    item_fn: &ItemFn,
    symbols: &RecoverySymbols<'_>,
    declared_names: &BTreeSet<String>,
) {
    let key = qualified_key(modules, owner, &item_fn.sig.ident.to_string());
    insert_node(
        program,
        FunctionNode::from_block(
            key,
            owner.map(str::to_owned),
            &item_fn.block,
            symbols.unknown_patterns,
            *symbols,
            declared_names,
        ),
    );
}

fn insert_node(program: &mut Program, node: FunctionNode) {
    let short = node.key.rsplit("::").next().unwrap_or(&node.key).to_owned();
    program
        .by_name
        .entry(short)
        .or_default()
        .push(node.key.clone());
    program.nodes.insert(node.key.clone(), node);
}

impl FunctionNode {
    fn from_block(
        key: String,
        owner: Option<String>,
        block: &Block,
        unknown_patterns: &[&str],
        symbols: RecoverySymbols<'_>,
        declared_names: &BTreeSet<String>,
    ) -> Self {
        let mut calls = CallCollector::default();
        calls.visit_block(block);
        let mut paths = PathCollector::new(symbols, declared_names);
        paths.visit_block(block);
        let mut unknown_arms = UnknownArmCollector {
            patterns: unknown_patterns,
            arms: Vec::new(),
            symbols,
            declared_names,
        };
        unknown_arms.visit_block(block);
        Self {
            key,
            owner,
            calls: calls.calls,
            call_paths: paths.paths,
            opaque_regions: paths.opaque_regions,
            path_overflowed: paths.overflowed,
            unknown_arm_paths: unknown_arms.arms,
        }
    }
}

fn qualified_key(modules: &[String], owner: Option<&str>, name: &str) -> String {
    modules
        .iter()
        .map(String::as_str)
        .chain(owner)
        .chain([name])
        .collect::<Vec<_>>()
        .join("::")
}

fn type_tail(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

#[derive(Default)]
struct CallCollector {
    calls: Vec<Call>,
}

impl CallCollector {
    fn push_call(&mut self, call: Call) {
        self.calls.push(call);
    }
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        self.visit_expr(&expression.func);
        for argument in &expression.args {
            self.visit_expr(argument);
        }
        if let Expr::Path(path) = expression.func.as_ref()
            && let Some(last) = path.path.segments.last()
        {
            self.push_call(Call {
                kind: CallKind::Function,
                name: last.ident.to_string(),
                shape: compact_tokens(expression),
                site: None,
            });
        }
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.visit_expr(&expression.receiver);
        for argument in &expression.args {
            self.visit_expr(argument);
        }
        let name = expression.method.to_string();
        if matches!(expression.receiver.as_ref(), Expr::Path(path) if path.path.is_ident("self")) {
            self.push_call(Call {
                kind: CallKind::SelfMethod,
                name,
                shape: compact_tokens(expression),
                site: None,
            });
        } else {
            self.push_call(Call {
                kind: CallKind::Method,
                name,
                shape: compact_tokens(expression),
                site: None,
            });
        }
    }
}

const MAX_CONTROL_FLOW_PATHS: usize = 4096;

struct PathCollector<'a> {
    paths: Vec<Vec<Call>>,
    opaque_regions: Vec<OpaqueRegion>,
    overflowed: bool,
    next_site: usize,
    symbols: RecoverySymbols<'a>,
    declared_names: &'a BTreeSet<String>,
}

impl<'a> PathCollector<'a> {
    fn new(symbols: RecoverySymbols<'a>, declared_names: &'a BTreeSet<String>) -> Self {
        Self {
            paths: vec![Vec::new()],
            opaque_regions: Vec::new(),
            overflowed: false,
            next_site: 0,
            symbols,
            declared_names,
        }
    }

    fn push_call(&mut self, mut call: Call) {
        let direct = classify_call(&call, self.symbols).is_some()
            || self
                .symbols
                .unknown_terminal_calls
                .iter()
                .any(|anchor| anchor.matches(&call))
            || self.symbols.retry_calls.contains(&call.name())
            || (call.name() == "mutate" && call.shape.contains("self.store.mutate"));
        if !direct && !self.declared_names.contains(call.name()) {
            return;
        }
        call.site = Some(self.next_site);
        self.next_site = self.next_site.saturating_add(1);
        if !direct {
            call.shape.clear();
        }
        for path in &mut self.paths {
            path.push(call.clone());
        }
    }

    fn normalize_paths(&mut self) {
        let unique = std::mem::take(&mut self.paths)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if unique.len() > MAX_CONTROL_FLOW_PATHS {
            self.overflowed = true;
        }
        self.paths = unique.into_iter().take(MAX_CONTROL_FLOW_PATHS).collect();
    }

    fn record_opaque(&mut self, kind: &'static str, expression: &impl ToTokens) {
        let parsed = expression.to_token_stream();
        let Ok(expression) = syn::parse2::<Expr>(parsed) else {
            self.overflowed = true;
            return;
        };
        let mut calls = CallCollector::default();
        calls.visit_expr(&expression);
        self.opaque_regions.push(OpaqueRegion {
            kind,
            calls: calls.calls,
        });
    }
}

impl<'ast> Visit<'ast> for PathCollector<'_> {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        self.visit_expr(&expression.func);
        for argument in &expression.args {
            self.visit_expr(argument);
        }
        if let Expr::Path(path) = expression.func.as_ref()
            && let Some(last) = path.path.segments.last()
        {
            self.push_call(Call {
                kind: CallKind::Function,
                name: last.ident.to_string(),
                shape: compact_tokens(expression),
                site: None,
            });
        }
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.visit_expr(&expression.receiver);
        for argument in &expression.args {
            self.visit_expr(argument);
        }
        let name = expression.method.to_string();
        let kind = if matches!(expression.receiver.as_ref(), Expr::Path(path) if path.path.is_ident("self"))
        {
            CallKind::SelfMethod
        } else {
            CallKind::Method
        };
        self.push_call(Call {
            kind,
            name,
            shape: compact_tokens(expression),
            site: None,
        });
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.visit_expr(&expression.cond);
        let prefix = self.paths.clone();
        self.visit_block(&expression.then_branch);
        let mut merged = std::mem::take(&mut self.paths);
        self.paths = prefix;
        if let Some((_, expression)) = &expression.else_branch {
            self.visit_expr(expression);
        }
        merged.append(&mut self.paths);
        self.paths = merged;
        self.normalize_paths();
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.visit_expr(&expression.expr);
        let prefix = self.paths.clone();
        let mut merged = Vec::new();
        for arm in &expression.arms {
            self.paths = prefix.clone();
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            merged.append(&mut self.paths);
        }
        self.paths = merged;
        self.normalize_paths();
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.visit_block(&expression.body);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_expr(&expression.expr);
        let zero_iterations = self.paths.clone();
        self.visit_block(&expression.body);
        self.paths.extend(zero_iterations);
        self.normalize_paths();
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.visit_expr(&expression.cond);
        let zero_iterations = self.paths.clone();
        self.visit_block(&expression.body);
        self.paths.extend(zero_iterations);
        self.normalize_paths();
    }

    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        self.record_opaque("closure", expression);
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.record_opaque("inline async", expression);
    }
}

struct UnknownArmCollector<'a> {
    patterns: &'a [&'a str],
    arms: Vec<Vec<Vec<Call>>>,
    symbols: RecoverySymbols<'a>,
    declared_names: &'a BTreeSet<String>,
}

impl<'ast> Visit<'ast> for UnknownArmCollector<'_> {
    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        for arm in &expression.arms {
            if pattern_matches_any(&arm.pat, self.patterns) {
                let mut paths = PathCollector::new(self.symbols, self.declared_names);
                paths.visit_expr(&arm.body);
                self.arms.push(paths.paths);
            }
        }
        visit::visit_expr_match(self, expression);
    }
}

fn pattern_matches_any(pattern: &Pat, patterns: &[&str]) -> bool {
    let compact = pattern.to_token_stream().to_string().replace(' ', "");
    patterns.iter().any(|candidate| compact.contains(candidate))
}

fn resolve_call<'a>(
    program: &'a Program,
    current: &FunctionNode,
    call: &Call,
) -> Option<&'a FunctionNode> {
    if call.kind == CallKind::Method {
        return None;
    }
    if call.kind == CallKind::SelfMethod
        && let Some(owner) = current.owner.as_deref()
    {
        let key = current
            .key
            .rsplit_once("::")
            .map(|(prefix, _)| format!("{prefix}::{}", call.name))
            .unwrap_or_else(|| format!("{owner}::{}", call.name));
        if let Some(node) = program.nodes.get(&key) {
            return Some(node);
        }
    }
    let candidates = program.by_name.get(call.name())?;
    if candidates.len() != 1 {
        return None;
    }
    program.nodes.get(&candidates[0])
}

fn collect_reachable(
    program: &Program,
    node: &FunctionNode,
    reachable: &mut BTreeSet<String>,
    stack: &mut BTreeSet<String>,
) {
    if !reachable.insert(node.key.clone()) || !stack.insert(node.key.clone()) {
        return;
    }
    for call in &node.calls {
        if let Some(callee) = resolve_call(program, node, call) {
            collect_reachable(program, callee, reachable, stack);
        }
    }
    stack.remove(&node.key);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Intent,
    Permit,
    Effect,
    Completion,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventOccurrence {
    kind: Event,
    origin: String,
}

fn expand_event_paths(
    program: &Program,
    node: &FunctionNode,
    symbols: RecoverySymbols<'_>,
    stack: &mut BTreeSet<String>,
    memo: &mut BTreeMap<String, BTreeSet<Vec<EventOccurrence>>>,
) -> BTreeSet<Vec<EventOccurrence>> {
    if let Some(paths) = memo.get(&node.key) {
        return paths.clone();
    }
    if !stack.insert(node.key.clone()) {
        return BTreeSet::from([Vec::new()]);
    }
    let mut output = BTreeSet::new();
    for call_path in &node.call_paths {
        let mut event_paths = BTreeSet::from([Vec::new()]);
        for call in call_path {
            if let Some(event) = classify_call(call, symbols) {
                event_paths = event_paths
                    .into_iter()
                    .map(|mut events| {
                        events.push(EventOccurrence {
                            kind: event,
                            origin: event_origin(node, call),
                        });
                        events
                    })
                    .collect();
            } else if let Some(callee) = resolve_call(program, node, call) {
                let callee_paths = expand_event_paths(program, callee, symbols, stack, memo);
                let mut joined = BTreeSet::new();
                for prefix in &event_paths {
                    for suffix in &callee_paths {
                        let mut events = prefix.clone();
                        let edge = event_origin(node, call);
                        events.extend(suffix.iter().map(|occurrence| EventOccurrence {
                            kind: occurrence.kind,
                            origin: format!("{edge}>{}", occurrence.origin),
                        }));
                        joined.insert(events);
                    }
                }
                event_paths = joined;
            }
        }
        output.extend(event_paths);
    }
    stack.remove(&node.key);
    memo.insert(node.key.clone(), output.clone());
    output
}

fn event_origin(node: &FunctionNode, call: &Call) -> String {
    format!("{}#{}", node.key, call.site.unwrap_or(usize::MAX))
}

fn classify_call(call: &Call, symbols: RecoverySymbols<'_>) -> Option<Event> {
    [
        (symbols.intent_calls, Event::Intent),
        (symbols.permit_calls, Event::Permit),
        (symbols.effect_calls, Event::Effect),
        (symbols.completion_calls, Event::Completion),
    ]
    .into_iter()
    .find_map(|(anchors, event)| {
        anchors
            .iter()
            .any(|anchor| anchor.matches(call))
            .then_some(event)
    })
}

fn compact_tokens(tokens: &impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn validate_event_paths(entry: &str, paths: &BTreeSet<Vec<EventOccurrence>>) -> Vec<Finding<Rule>> {
    let expected = [
        Event::Intent,
        Event::Permit,
        Event::Effect,
        Event::Completion,
    ];
    let effect_paths = paths
        .iter()
        .filter(|events| events.iter().any(|event| event.kind == Event::Effect))
        .collect::<Vec<_>>();
    let valid = effect_paths
        .iter()
        .filter(|events| {
            events.len().is_multiple_of(expected.len())
                && events
                    .chunks_exact(expected.len())
                    .all(|cycle| cycle.iter().map(|occurrence| occurrence.kind).eq(expected))
        })
        .copied()
        .collect::<Vec<_>>();
    let invalid = effect_paths
        .iter()
        .filter(|events| {
            let is_valid = valid.contains(events);
            let is_failed_effect_prefix = events
                .last()
                .is_some_and(|event| event.kind == Event::Effect)
                && valid.iter().any(|candidate| candidate.starts_with(events));
            !is_valid && !is_failed_effect_prefix
        })
        .take(4)
        .map(|events| {
            let path = events
                .iter()
                .map(|event| format!("{:?}@{}", event.kind, event.origin))
                .collect::<Vec<_>>();
            format!("[{}]", path.join(", "))
        })
        .collect::<Vec<_>>();
    if !valid.is_empty() && invalid.is_empty() {
        return Vec::new();
    }
    let detail = if effect_paths.is_empty() {
        "no production-reachable effect-bearing path was found".to_owned()
    } else {
        format!("invalid paths: [{}]", invalid.join(", "))
    };
    vec![finding(
        Rule::LiveEffectOrder,
        entry,
        format!(
            "every reachable effect-bearing path must be exactly intent -> permit -> effect -> completion; {detail}"
        ),
    )]
}

fn calls_reach_named(
    program: &Program,
    current: &FunctionNode,
    calls: &[Call],
    targets: &[&str],
    stack: &mut BTreeSet<String>,
) -> bool {
    for call in calls {
        if targets.contains(&call.name()) {
            return true;
        }
        let Some(callee) = resolve_call(program, current, call) else {
            continue;
        };
        if !stack.insert(callee.key.clone()) {
            continue;
        }
        let found = calls_reach_named(program, callee, &callee.calls, targets, stack);
        stack.remove(&callee.key);
        if found {
            return true;
        }
    }
    false
}

fn calls_reach_anchors(
    program: &Program,
    current: &FunctionNode,
    calls: &[Call],
    targets: &[CallAnchor<'_>],
    stack: &mut BTreeSet<String>,
) -> bool {
    for call in calls {
        if targets.iter().any(|target| target.matches(call)) {
            return true;
        }
        let Some(callee) = resolve_call(program, current, call) else {
            continue;
        };
        if !stack.insert(callee.key.clone()) {
            continue;
        }
        let found = calls_reach_anchors(program, callee, &callee.calls, targets, stack);
        stack.remove(&callee.key);
        if found {
            return true;
        }
    }
    false
}

fn collect_legacy_hits(program: &mut Program, path: &Path, item: &Item, legacy_idents: &[&str]) {
    struct LegacyVisitor<'a> {
        legacy: &'a [&'a str],
        hits: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for LegacyVisitor<'_> {
        fn visit_item(&mut self, item: &'ast Item) {
            if !item_is_test_only(item) {
                visit::visit_item(self, item);
            }
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if !attrs_are_test_only(&item.attrs) {
                visit::visit_impl_item_fn(self, item);
            }
        }

        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            let value = ident.to_string();
            if self.legacy.contains(&value.as_str()) {
                self.hits.insert(value);
            }
        }
    }
    let mut visitor = LegacyVisitor {
        legacy: legacy_idents,
        hits: BTreeSet::new(),
    };
    visitor.visit_item(item);
    program.legacy_hits.extend(
        visitor
            .hits
            .into_iter()
            .map(|ident| (path.display().to_string(), ident)),
    );
}

fn item_is_test_only(item: &Item) -> bool {
    attrs_are_test_only(match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    })
}

fn attrs_are_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let compact = attribute
            .meta
            .to_token_stream()
            .to_string()
            .replace(' ', "");
        compact == "cfg(test)" || compact.starts_with("cfg(all(test,")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTENT: &[CallAnchor<'static>] = &[CallAnchor::named("record_intent")];
    const PERMIT: &[CallAnchor<'static>] = &[CallAnchor::named("issue_permit")];
    const EFFECT: &[CallAnchor<'static>] = &[CallAnchor::named("invoke_effect")];
    const COMPLETION: &[CallAnchor<'static>] = &[CallAnchor::named("commit_completion")];
    const UNKNOWN: &[&str] = &["ProbeOutcome::Unknown"];
    const OPERATOR: &[CallAnchor<'static>] = &[CallAnchor::named("require_operator")];
    const RETRY: &[&str] = &["retry_effect"];
    const LEGACY: &[&str] = &[
        "SagaInstanceStore",
        "SagaJournal",
        "SagaReceiptStore",
        "SagaRuntimeLock",
        "SagaJournalAppendOutcome",
        "SagaJournalAppendRecord",
        "RuntimeLockUnavailable",
        "RuntimeLockLost",
        "RuntimeLockRenewUnknown",
        "OwnerCheckpointStore",
    ];

    fn symbols() -> RecoverySymbols<'static> {
        RecoverySymbols {
            entry: "Executor::execute_recovery",
            intent_calls: INTENT,
            permit_calls: PERMIT,
            effect_calls: EFFECT,
            completion_calls: COMPLETION,
            completion_commit: None,
            unknown_patterns: UNKNOWN,
            unknown_terminal_calls: OPERATOR,
            retry_calls: RETRY,
            legacy_idents: LEGACY,
        }
    }

    fn scan(source: &str) -> Result<Vec<Finding<Rule>>> {
        analyze_sources(
            &[(Path::new("crates/eventexec/src/saga.rs"), source)],
            symbols(),
        )
    }

    fn has(findings: &[Finding<Rule>], rule: Rule) -> bool {
        findings.iter().any(|finding| finding.rule == rule)
    }

    #[test]
    fn marked_anchor_requires_the_real_typed_transition_shape() {
        let anchor = CallAnchor::marked("mutate", "SagaDurableMutation::ForwardIntent");
        let real = Call {
            kind: CallKind::SelfMethod,
            name: "mutate".to_owned(),
            shape: "self.mutate(SagaDurableMutation::ForwardIntent(intent))".to_owned(),
            site: None,
        };
        let bait = Call {
            kind: CallKind::SelfMethod,
            name: "mutate".to_owned(),
            shape: "self.mutate(unrelated)".to_owned(),
            site: None,
        };
        assert!(anchor.matches(&real));
        assert!(!anchor.matches(&bait));
    }

    #[test]
    fn call_path_preserves_permit_before_effect() -> Result<()> {
        let expression = syn::parse_str::<Expr>(
            "action.do_it(result.and_then(|context| SagaForwardPermit::new(context, lease, intent)))",
        )?;
        let declared = BTreeSet::new();
        let mut paths = PathCollector::new(forward_symbols(), &declared);
        paths.visit_expr(&expression);
        let events = paths.paths[0]
            .iter()
            .filter_map(|call| classify_call(call, forward_symbols()))
            .collect::<Vec<_>>();
        assert_eq!(events, vec![Event::Permit, Event::Effect]);
        Ok(())
    }

    const GREEN: &str = r#"
        enum ProbeOutcome { Applied, NotApplied, Unknown }
        struct Executor;
        impl Executor {
            fn execute_recovery(&self, outcome: ProbeOutcome) {
                self.persist_then_run();
                match outcome {
                    ProbeOutcome::Unknown => self.require_operator(),
                    _ => self.finish(),
                }
            }
            fn persist_then_run(&self) {
                self.record_intent();
                self.issue_permit();
                self.invoke_effect();
                self.commit_completion();
            }
            fn require_operator(&self) {}
            fn finish(&self) {}
            fn record_intent(&self) {}
            fn issue_permit(&self) {}
            fn invoke_effect(&self) {}
            fn commit_completion(&self) {}
        }
    "#;

    #[test]
    fn synthetic_green_follows_reachable_wrappers_and_unknown_operator_path() -> Result<()> {
        assert!(scan(GREEN)?.is_empty());
        Ok(())
    }

    #[test]
    fn synthetic_red_rejects_mutually_unreachable_event_fragments() -> Result<()> {
        let if_false = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self) {
                    if false { self.record_intent(); }
                    self.issue_permit();
                    self.invoke_effect();
                    self.commit_completion();
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(if_false)?, Rule::LiveEffectOrder));

        let mutually_exclusive_if = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self, choose_intent: bool) {
                    if choose_intent {
                        self.record_intent(); self.issue_permit();
                    } else {
                        self.invoke_effect(); self.commit_completion();
                    }
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(mutually_exclusive_if)?, Rule::LiveEffectOrder));

        let split_match_arms = r#"
            enum Choice { Intent, Effect }
            struct Executor;
            impl Executor {
                fn execute_recovery(&self, choice: Choice) {
                    match choice {
                        Choice::Intent => { self.record_intent(); self.issue_permit(); }
                        Choice::Effect => { self.invoke_effect(); self.commit_completion(); }
                    }
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(split_match_arms)?, Rule::LiveEffectOrder));

        let incomplete_sibling = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self, complete: bool) {
                    if complete {
                        self.record_intent(); self.issue_permit();
                        self.invoke_effect(); self.commit_completion();
                    } else {
                        self.record_intent(); self.issue_permit(); self.invoke_effect();
                    }
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(incomplete_sibling)?, Rule::LiveEffectOrder));

        let opaque_closure = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self) {
                    self.record_intent(); self.issue_permit();
                    let deferred = || self.invoke_effect();
                    deferred();
                    self.commit_completion();
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(opaque_closure)?, Rule::LiveEffectOrder));

        let opaque_async = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self) {
                    self.record_intent(); self.issue_permit();
                    let deferred = async { self.invoke_effect(); };
                    self.commit_completion();
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(opaque_async)?, Rule::LiveEffectOrder));
        Ok(())
    }

    #[test]
    fn synthetic_red_rejects_before_intent_blind_retry_alias_wrapper_dead_helper_string_and_cfg_test_bait()
    -> Result<()> {
        let before_intent = GREEN.replace(
            "self.record_intent();\n                self.issue_permit();\n                self.invoke_effect();",
            "self.invoke_effect();\n                self.record_intent();\n                self.issue_permit();",
        );
        assert!(has(&scan(&before_intent)?, Rule::LiveEffectOrder));

        let blind_retry = GREEN.replace(
            "ProbeOutcome::Unknown => self.require_operator()",
            "ProbeOutcome::Unknown => self.retry_wrapper()",
        ).replace(
            "fn require_operator(&self) {}",
            "fn require_operator(&self) {} fn retry_wrapper(&self) { self.retry_effect(); } fn retry_effect(&self) {}",
        );
        assert!(has(&scan(&blind_retry)?, Rule::UnknownNeverRetries));

        let alias = format!("type HiddenStore = SagaInstanceStore; {GREEN}");
        assert!(has(&scan(&alias)?, Rule::LegacyTopologyAbsent));

        let split_capabilities = r#"
            enum SagaCapabilityRequirement {
                TypedActions,
                InstanceStore,
                JournalStore,
                ReceiptStore,
                CheckpointStore,
                DeadLetterStore,
                LockFencing,
                Worker,
                Probe,
            }
        "#;
        assert!(saga_capability_schema_drift(split_capabilities)?.is_some());
        let unified_capabilities = r#"
            enum SagaCapabilityRequirement {
                TypedActions,
                DefinitionRegistry,
                DurableStore,
                Hydrator,
                EffectProbe,
                DeadLetterStore,
                Worker,
                Readiness,
            }
        "#;
        assert!(saga_capability_schema_drift(unified_capabilities)?.is_none());

        let wrapper = GREEN.replace(
            "self.record_intent();\n                self.issue_permit();\n                self.invoke_effect();\n                self.commit_completion();",
            "self.effect_wrapper();\n                self.record_intent();\n                self.issue_permit();\n                self.commit_completion();",
        ).replace(
            "fn invoke_effect(&self) {}",
            "fn effect_wrapper(&self) { self.invoke_effect(); } fn invoke_effect(&self) {}",
        );
        assert!(has(&scan(&wrapper)?, Rule::LiveEffectOrder));

        let dead_helper = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self) { self.invoke_effect(); }
                fn compliant_but_dead(&self) {
                    self.record_intent(); self.issue_permit(); self.invoke_effect(); self.commit_completion();
                }
                fn record_intent(&self) {} fn issue_permit(&self) {}
                fn invoke_effect(&self) {} fn commit_completion(&self) {}
            }
        "#;
        assert!(has(&scan(dead_helper)?, Rule::LiveEffectOrder));

        let string_bait = r#"
            struct Executor;
            impl Executor {
                fn execute_recovery(&self) {
                    let _ = "record_intent issue_permit invoke_effect commit_completion";
                }
            }
        "#;
        assert!(has(&scan(string_bait)?, Rule::LiveEffectOrder));

        let cfg_test_bait = r#"
            struct Executor;
            impl Executor { fn execute_recovery(&self) {} }
            #[cfg(test)]
            mod bait {
                impl super::Executor {
                    fn compliant(&self) {
                        self.record_intent(); self.issue_permit(); self.invoke_effect(); self.commit_completion();
                    }
                }
            }
        "#;
        assert!(has(&scan(cfg_test_bait)?, Rule::LiveEffectOrder));
        Ok(())
    }

    #[test]
    fn synthetic_red_rejects_all_legacy_topology_identifiers_but_not_strings_or_tests() -> Result<()>
    {
        for legacy in LEGACY {
            let source = format!("struct {legacy}; {GREEN}");
            assert!(
                has(&scan(&source)?, Rule::LegacyTopologyAbsent),
                "legacy identifier escaped: {legacy}"
            );
        }
        let bait = format!(
            "const BAIT: &str = \"{}\"; #[cfg(test)] mod tests {{ struct SagaRuntimeLock; }} {GREEN}",
            LEGACY.join(" ")
        );
        assert!(scan(&bait)?.is_empty(), "string/test bait must be ignored");
        Ok(())
    }

    #[test]
    fn executor_rejects_caller_chosen_definition_dual_truth() -> Result<()> {
        let closed = r#"
            pub struct SagaStartRequest {
                instance: SagaInstanceRef,
            }
            pub trait SagaExecutor {
                fn advance_registered(
                    &self,
                    instance: SagaInstanceRef,
                    listed_definition: consistency::SagaDefinitionIdentity,
                );
            }
        "#;
        assert!(executor_has_pinned_definition_boundary(closed)?);

        let dual_truth_start = r#"
            pub struct SagaStartRequest {
                instance: SagaInstanceRef,
                definition: SagaDefinitionIdentity,
            }
            pub trait SagaExecutor {
                fn advance_registered(
                    &self,
                    instance: SagaInstanceRef,
                    listed_definition: consistency::SagaDefinitionIdentity,
                );
            }
        "#;
        assert!(!executor_has_pinned_definition_boundary(dual_truth_start)?);

        let suffix_spoof = r#"
            pub struct SagaStartRequest {
                instance: SagaInstanceRef,
            }
            pub trait SagaExecutor {
                fn advance_registered(
                    &self,
                    instance: SagaInstanceRef,
                    listed_definition: FakeSagaDefinitionIdentity,
                );
            }
        "#;
        assert!(!executor_has_pinned_definition_boundary(suffix_spoof)?);

        let wrong_start_type = r#"
            pub struct SagaStartRequest {
                instance: String,
            }
            pub trait SagaExecutor {
                fn advance_registered(
                    &self,
                    instance: SagaInstanceRef,
                    listed_definition: SagaDefinitionIdentity,
                );
            }
        "#;
        assert!(!executor_has_pinned_definition_boundary(wrong_start_type)?);

        let missing_listing_pin = r#"
            pub struct SagaStartRequest {
                instance: SagaInstanceRef,
            }
            pub trait SagaExecutor {
                fn advance_registered(&self, instance: SagaInstanceRef);
            }
        "#;
        assert!(!executor_has_pinned_definition_boundary(
            missing_listing_pin
        )?);

        let legacy_run = r#"
            pub struct SagaStartRequest {
                instance: SagaInstanceRef,
            }
            pub trait SagaExecutor {
                fn run(&self, instance: SagaInstanceRef);
            }
        "#;
        assert!(!executor_has_pinned_definition_boundary(legacy_run)?);
        Ok(())
    }

    #[test]
    fn integration_test_subtree_is_excluded_from_production_sources() -> Result<()> {
        let fixture = TempRoot::new("integration-test-subtree")?;
        for source_root in ["crates", "adapters"] {
            std::fs::create_dir_all(fixture.path.join(source_root))?;
        }
        let support = fixture
            .path
            .join("adapters/postgres/src/integration_tests/support/helpers.rs");
        std::fs::create_dir_all(support.parent().context("support parent")?)?;
        std::fs::write(&support, "struct SagaRuntimeLock;\n")?;
        let production = fixture.path.join("crates/live/src/lib.rs");
        std::fs::create_dir_all(production.parent().context("production parent")?)?;
        std::fs::write(&production, "pub struct Live;\n")?;

        let sources = production_sources(&fixture.path)?;
        assert_eq!(
            sources
                .iter()
                .map(|(path, _)| path.as_path())
                .collect::<Vec<_>>(),
            [std::path::Path::new("crates/live/src/lib.rs")],
            "production sources must remain non-empty while crate-internal integration modules stay excluded"
        );
        Ok(())
    }

    #[test]
    fn workspace_saga_recovery_flow_is_live() -> Result<()> {
        let (summary, findings) = SagaDurableRecoveryGuard.check()?;
        assert!(summary.contains("2 live Saga effect flows"), "{summary}");
        assert!(summary.contains("single SagaDurableStore"), "{summary}");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    struct TempRoot {
        path: std::path::PathBuf,
    }

    impl TempRoot {
        fn new(name: &str) -> Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "rss-saga-durable-recovery-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            if root.exists() {
                std::fs::remove_dir_all(&root)?;
            }
            std::fs::create_dir_all(&root)?;
            Ok(Self { path: root })
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
