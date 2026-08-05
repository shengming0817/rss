//! Projection target production enrollment guard (#1917).
//!
//! The structured invariant record lives beside the `runtime-baseline` gate owner; this module is
//! its internal AST implementation.

use crate::diagnostic::{Finding, finding};
use crate::localtx_coverage::attrs_may_be_production;
use crate::runtime_baseline::Rule;
use anyhow::{Context, Result};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use syn::parse::{Parse, ParseStream, Parser as _};
use syn::visit::Visit;

const EVENTEXEC_PROJECTION_OWNER: &str = "crates/eventexec/src/projection.rs";
const PROJECTION_CATALOG_OWNER: &str = "crates/testkit/src/projection_conformance.rs";
const LEGACY_IDENTS: [&str; 3] = [
    "ProjectionReplayTarget",
    "ProjectionReplayProjector",
    "replay_target",
];

#[derive(Debug)]
struct Package {
    name: String,
    relative: PathBuf,
    all_sources: BTreeSet<PathBuf>,
    tracked_sources: BTreeSet<PathBuf>,
    production_sources: BTreeSet<PathBuf>,
    test_sources: BTreeSet<PathBuf>,
    test_target_sources: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
}

#[derive(Debug, Clone)]
struct StoreImpl {
    owner: String,
    store: String,
}

struct Enrollment {
    source: PathBuf,
    cases: Vec<EnrollmentCase>,
    parse_error: Option<String>,
    statically_disabled: bool,
}

struct EnrollmentCase {
    case: String,
    runner: String,
    behavior: String,
    test_attributes: Vec<syn::Attribute>,
}

pub(crate) fn findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }
    let packages = packages(root)?;
    let canonical_cases = canonical_cases(root)?;
    let models_eventexec = packages
        .iter()
        .any(|package| package.relative == Path::new("crates/eventexec"));
    // Generic runtime-baseline fixtures intentionally model only the assembly anchors. Dedicated
    // projection fixtures and the real workspace include eventexec and therefore fail closed.
    if !models_eventexec {
        return Ok(Vec::new());
    }
    let (stores, mut findings) = enrollment_findings(root, &packages, &canonical_cases)?;
    findings.extend(runtime_funnel_findings(root, &packages)?);
    if stores.is_empty() {
        findings.extend(disabled_activation_findings(root)?);
    }
    Ok(findings)
}

fn enrollment_findings(
    root: &Path,
    packages: &[Package],
    canonical_cases: &[String],
) -> Result<(Vec<StoreImpl>, Vec<Finding<Rule>>)> {
    let mut stores = Vec::new();
    let mut findings = Vec::new();
    for package in packages {
        let package_stores = scan_package_stores(root, package, &mut findings)?;
        let is_reference_carrier = package.relative == Path::new("crates/eventexec");
        if package_stores.is_empty() && !is_reference_carrier {
            continue;
        }
        stores.extend(package_stores.iter().cloned());
        let enrollments = package_enrollments(package)?;
        findings.extend(enrollment_edge_findings(
            root,
            package,
            &package_stores,
            &enrollments,
            is_reference_carrier,
        )?);
        for enrollment in &enrollments {
            findings.extend(validate_enrollment(
                root,
                package,
                enrollment,
                canonical_cases,
            )?);
        }
    }
    Ok((stores, findings))
}

fn scan_package_stores(
    root: &Path,
    package: &Package,
    findings: &mut Vec<Finding<Rule>>,
) -> Result<Vec<StoreImpl>> {
    let mut stores = Vec::new();
    for source in &package.production_sources {
        let relative = relative_string(root, source);
        let file = parse_file(source)?;
        let mut visitor = ProductionImplVisitor::default();
        visitor.visit_file(&file);
        if !visitor.store_impls.is_empty() {
            findings.extend(opaque_codegen_findings(root, source)?);
        }
        if visitor.store_macro_bypasses > 0 || visitor.store_alias_bypasses > 0 {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative.clone(),
                "predicate=projection_target_store_ast_bypass: ProjectionTargetStore impls must use the canonical trait name in source AST rather than macro or renamed-import indirection",
            ));
        }
        stores.extend(visitor.store_impls.into_iter().map(|store| StoreImpl {
            owner: relative.clone(),
            store,
        }));
    }
    for source in package.all_sources.difference(&package.tracked_sources) {
        let file = parse_file(source)?;
        let mut visitor = ProductionImplVisitor::default();
        visitor.visit_file(&file);
        if !visitor.store_impls.is_empty()
            || visitor.store_macro_bypasses > 0
            || visitor.store_alias_bypasses > 0
        {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative_string(root, source),
                "predicate=projection_target_tracked_source: untracked Rust source contains a ProjectionTargetStore impl",
            ));
        }
    }
    Ok(stores)
}

fn enrollment_edge_findings(
    root: &Path,
    package: &Package,
    stores: &[StoreImpl],
    enrollments: &[Enrollment],
    is_reference_carrier: bool,
) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    let expected = if is_reference_carrier && stores.is_empty() {
        1
    } else {
        stores.len()
    };
    if enrollments.len() != expected {
        let impls = stores
            .iter()
            .map(|store| format!("{}@{}", store.store, store.owner))
            .collect::<Vec<_>>();
        findings.push(finding(
            Rule::MissingStructuralEvidence,
            package.relative.join("Cargo.toml").to_string_lossy(),
            format!(
                "predicate=projection_target_enrollment_count: package `{}` owns {} production store impl(s) {impls:?} (reference_carrier={is_reference_carrier}) but {} canonical enrollments; expected {expected}",
                package.name,
                stores.len(),
                enrollments.len(),
            ),
        ));
    }
    for store in stores {
        let mut matching = 0;
        for enrollment in enrollments {
            matching += usize::from(enrollment_targets_store(package, enrollment, &store.store)?);
        }
        if matching != 1 {
            findings.push(finding(
                Rule::MissingStructuralEvidence,
                store.owner.clone(),
                format!(
                    "predicate=projection_target_impl_enrollment: concrete store `{}` must have exactly one canonical enrollment whose target funnel accepts that store; got {matching}",
                    store.store
                ),
            ));
        }
    }
    for enrollment in enrollments {
        let mut matching = Vec::new();
        for store in stores {
            if enrollment_targets_store(package, enrollment, &store.store)? {
                matching.push(store.store.as_str());
            }
        }
        if !stores.is_empty() && matching.len() != 1 {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative_string(root, &enrollment.source),
                format!(
                    "predicate=projection_target_enrollment_impl_edge: each canonical enrollment must target exactly one concrete ProjectionTargetStore impl; got {matching:?}"
                ),
            ));
        }
    }
    Ok(findings)
}

fn validate_enrollment(
    root: &Path,
    package: &Package,
    enrollment: &Enrollment,
    canonical_cases: &[String],
) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    if let Some(error) = &enrollment.parse_error {
        findings.push(finding(
            Rule::ForbiddenWiring,
            relative_string(root, &enrollment.source),
            format!("predicate=projection_target_exact_set: {error}"),
        ));
        return Ok(findings);
    }
    let actual = enrollment
        .cases
        .iter()
        .map(|case| case.case.as_str())
        .collect::<Vec<_>>();
    if actual != canonical_cases {
        findings.push(finding(
            Rule::ForbiddenWiring,
            relative_string(root, &enrollment.source),
            format!(
                "predicate=projection_target_exact_set: expected {canonical_cases:?}, got {actual:?}"
            ),
        ));
    }
    let runners = enrollment
        .cases
        .iter()
        .map(|case| case.runner.as_str())
        .collect::<BTreeSet<_>>();
    let behaviors = enrollment
        .cases
        .iter()
        .map(|case| case.behavior.as_str())
        .collect::<BTreeSet<_>>();
    if runners.len() != canonical_cases.len() || behaviors.len() != canonical_cases.len() {
        findings.push(finding(
            Rule::ForbiddenWiring,
            relative_string(root, &enrollment.source),
            "predicate=projection_target_unique_edges: every canonical wrapper must have one unique behavior edge",
        ));
    }
    if !reachable_test_source(package, &enrollment.source) {
        findings.push(finding(
            Rule::MissingStructuralEvidence,
            relative_string(root, &enrollment.source),
            "predicate=projection_target_reachable_test: enrollment is not owned by a reachable Cargo lib/bin/test target",
        ));
    }
    let invalid_registration = enrollment.statically_disabled
        || enrollment.cases.iter().any(|case| {
            case.test_attributes.len() != 1
                || !case.test_attributes[0]
                    .path()
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .eq(["tokio", "test"])
        });
    if invalid_registration {
        findings.push(finding(
            Rule::ForbiddenWiring,
            relative_string(root, &enrollment.source),
            "predicate=projection_target_async_test_registration: every runner must be an enabled item with exactly one #[tokio::test] registration; #[test], missing, ignored, cfg/cfg_attr-disabled, and extra attributes are rejected",
        ));
    }
    findings.extend(behavior_findings(root, package, enrollment)?);
    Ok(findings)
}

fn canonical_cases(root: &Path) -> Result<Vec<String>> {
    let source = root.join(PROJECTION_CATALOG_OWNER);
    let file = parse_file(&source)?;
    let mut catalogs = Vec::new();
    for item in file.items {
        let syn::Item::Impl(item_impl) = item else {
            continue;
        };
        if last_ident(&item_impl.self_ty) != "ProjectionCase" {
            continue;
        }
        for item in item_impl.items {
            let syn::ImplItem::Const(item_const) = item else {
                continue;
            };
            if item_const.ident != "ALL" {
                continue;
            }
            let syn::Expr::Array(array) = unwrap_expression(&item_const.expr) else {
                continue;
            };
            let cases = array
                .elems
                .iter()
                .map(|element| {
                    let syn::Expr::Path(path) = unwrap_expression(element) else {
                        anyhow::bail!("ProjectionCase::ALL entries must be enum paths");
                    };
                    let variant = path
                        .path
                        .segments
                        .last()
                        .context("ProjectionCase::ALL entry has no variant")?
                        .ident
                        .to_string();
                    Ok(camel_to_snake(&variant))
                })
                .collect::<Result<Vec<_>>>()?;
            catalogs.push(cases);
        }
    }
    match catalogs.as_slice() {
        [catalog] if !catalog.is_empty() => Ok(catalog.clone()),
        _ => anyhow::bail!(
            "{} must own exactly one non-empty ProjectionCase::ALL catalog",
            source.display()
        ),
    }
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            output.push('_');
        }
        output.extend(character.to_lowercase());
    }
    output
}

fn enrollment_targets_store(
    package: &Package,
    enrollment: &Enrollment,
    store: &str,
) -> Result<bool> {
    let functions = package_functions(package, &enrollment.source)?;
    let Some(target) = unique_function(&functions, "target") else {
        return Ok(false);
    };
    let Some(syn::FnArg::Typed(argument)) = target.sig.inputs.first() else {
        return Ok(false);
    };
    Ok(type_mentions_ident(&argument.ty, store))
}

fn type_mentions_ident(ty: &syn::Type, wanted: &str) -> bool {
    struct TypeIdent<'a> {
        wanted: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for TypeIdent<'_> {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.found |= ident == self.wanted;
        }
    }
    let mut visitor = TypeIdent {
        wanted,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}
fn opaque_codegen_findings(root: &Path, source: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    let relative = relative_string(root, source);
    let file = parse_file(source)?;
    let mut visitor = OpaqueCodegenVisitor {
        source: &relative,
        production: true,
        opaque: Vec::new(),
    };
    visitor.visit_file(&file);
    for entry in visitor.opaque {
        findings.push(finding(
            Rule::ForbiddenWiring,
            relative.clone(),
            format!(
                "predicate=projection_target_opaque_codegen: `{entry}` is an unexpandable production code-generation entrance in a concrete ProjectionTargetStore owner module"
            ),
        ));
    }
    Ok(findings)
}

fn behavior_findings(
    root: &Path,
    package: &Package,
    enrollment: &Enrollment,
) -> Result<Vec<Finding<Rule>>> {
    let functions = package_functions(package, &enrollment.source)?;
    let mut findings = Vec::new();
    let target_is_live = unique_function(&functions, "target").is_some_and(target_flow_is_live);
    let attempt_is_live = unique_function(&functions, "attempt").is_some_and(attempt_flow_is_live);
    let observation_is_live =
        unique_function(&functions, "observation").is_some_and(observation_flow_is_live);
    let rollback_observation_is_live = unique_function(&functions, "rollback_observation")
        .is_none_or(rollback_observation_flow_is_live);
    let pipeline_is_live =
        target_is_live && attempt_is_live && observation_is_live && rollback_observation_is_live;
    for case in &enrollment.cases {
        let behavior = case.behavior.rsplit("::").next().unwrap_or(&case.behavior);
        let Some(function) = functions.get(behavior).filter(|items| items.len() == 1) else {
            findings.push(finding(
                Rule::MissingStructuralEvidence,
                relative_string(root, &enrollment.source),
                format!(
                    "predicate=projection_target_behavior_edge: `{}` must resolve exactly once in the owning package",
                    case.behavior
                ),
            ));
            continue;
        };
        let behavior_is_live = resolved_behavior_is_live(&function[0], &functions);
        if !pipeline_is_live || !behavior_is_live {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative_string(root, &enrollment.source),
                format!(
                    "predicate=projection_target_behavior_live: `{}` must directly feed real target attempts through the unique wrapper→projector→harness→checkpoint flow and return observations derived from those attempts plus live store-local counts (store.counts) or durable owner-pool counts (`*_conformance_counts` + apply_calls); target={target_is_live} attempt={attempt_is_live} observation={observation_is_live} behavior={}",
                    case.behavior,
                    behavior_is_live,
                ),
            ));
        }
    }
    Ok(findings)
}

fn unique_function<'a>(
    functions: &'a BTreeMap<String, Vec<syn::ItemFn>>,
    name: &str,
) -> Option<&'a syn::ItemFn> {
    functions
        .get(name)
        .and_then(|items| match items.as_slice() {
            [item] => Some(item),
            _ => None,
        })
}

fn direct_locals(function: &syn::ItemFn) -> Vec<(String, &syn::Expr)> {
    function
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let syn::Pat::Ident(binding) = &local.pat else {
                return None;
            };
            Some((
                binding.ident.to_string(),
                local.init.as_ref()?.expr.as_ref(),
            ))
        })
        .collect()
}

fn tail_expression(function: &syn::ItemFn) -> Option<&syn::Expr> {
    match function.block.stmts.last()? {
        syn::Stmt::Expr(expression, None) => Some(expression),
        _ => None,
    }
}

fn unwrap_expression(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match expression {
            syn::Expr::Await(value) => &value.base,
            syn::Expr::Group(value) => &value.expr,
            syn::Expr::Paren(value) => &value.expr,
            syn::Expr::Reference(value) => &value.expr,
            syn::Expr::Try(value) => &value.expr,
            _ => return expression,
        };
    }
}

fn path_call<'a>(expression: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Call(call) = unwrap_expression(expression) else {
        return None;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    function
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
        .then_some(call)
}

fn contains_path_call(expression: &syn::Expr, owner: &str, method: &str) -> bool {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::Call(call) => {
            let matches = match call.func.as_ref() {
                syn::Expr::Path(path) => {
                    let segments = path
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>();
                    segments.ends_with(&[owner.to_owned(), method.to_owned()])
                }
                _ => false,
            };
            matches
                || call
                    .args
                    .iter()
                    .any(|argument| contains_path_call(argument, owner, method))
        }
        syn::Expr::MethodCall(call) => {
            contains_path_call(&call.receiver, owner, method)
                || call
                    .args
                    .iter()
                    .any(|argument| contains_path_call(argument, owner, method))
        }
        syn::Expr::Array(array) => array
            .elems
            .iter()
            .any(|element| contains_path_call(element, owner, method)),
        syn::Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|element| contains_path_call(element, owner, method)),
        syn::Expr::If(value) => {
            contains_path_call(&value.cond, owner, method)
                || value
                    .then_branch
                    .stmts
                    .iter()
                    .any(|statement| statement_contains_path_call(statement, owner, method))
                || value
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, expression)| contains_path_call(expression, owner, method))
        }
        syn::Expr::Match(value) => {
            contains_path_call(&value.expr, owner, method)
                || value
                    .arms
                    .iter()
                    .any(|arm| contains_path_call(&arm.body, owner, method))
        }
        syn::Expr::Block(value) => value
            .block
            .stmts
            .iter()
            .any(|statement| statement_contains_path_call(statement, owner, method)),
        _ => false,
    }
}

fn statement_contains_path_call(statement: &syn::Stmt, owner: &str, method: &str) -> bool {
    match statement {
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|init| contains_path_call(&init.expr, owner, method)),
        syn::Stmt::Expr(expression, _) => contains_path_call(expression, owner, method),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
    }
}

fn expression_mentions_ident(expression: &syn::Expr, wanted: &str) -> bool {
    if let syn::Expr::Macro(value) = expression
        && value.mac.path.is_ident("vec")
        && let Ok(items) =
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(value.mac.tokens.clone())
    {
        return items
            .iter()
            .any(|item| expression_mentions_ident(item, wanted));
    }
    struct IdentUse<'a> {
        wanted: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for IdentUse<'_> {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.found |= ident == self.wanted;
        }
    }
    let mut visitor = IdentUse {
        wanted,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

fn target_flow_is_live(function: &syn::ItemFn) -> bool {
    function.sig.asyncness.is_none()
        && tail_expression(function).is_some_and(|tail| {
            contains_path_call(tail, "ConformingProjectionTarget", "new")
                && expression_mentions_ident(tail, "store")
        })
}

fn attempt_flow_is_live(function: &syn::ItemFn) -> bool {
    if function.sig.asyncness.is_none() {
        return false;
    }
    let locals = direct_locals(function);
    let position = |name: &str| locals.iter().position(|(binding, _)| binding == name);
    let (Some(before), Some(harness), Some(run), Some(advanced)) = (
        position("before"),
        position("harness"),
        position("run"),
        position("advanced"),
    ) else {
        return false;
    };
    if !(before < harness && harness < run && run < advanced) {
        return false;
    }
    let before_expr = locals[before].1;
    let harness_expr = locals[harness].1;
    let run_expr = locals[run].1;
    let advanced_expr = locals[advanced].1;
    let run_is_awaited_harness = matches!(run_expr, syn::Expr::Await(_))
        && matches!(unwrap_expression(run_expr), syn::Expr::MethodCall(call)
            if call.method == "run" && expression_mentions_ident(&call.receiver, "harness"));
    let tail = tail_expression(function);
    expression_mentions_ident(before_expr, "checkpoint")
        && contains_path_call(harness_expr, "ProjectionHarness", "new")
        && contains_path_call(harness_expr, "ProjectionProjector", "with_execution")
        && expression_mentions_ident(harness_expr, "execution")
        && expression_mentions_ident(harness_expr, "target")
        && expression_mentions_ident(harness_expr, "checkpoint")
        && run_is_awaited_harness
        && expression_mentions_ident(advanced_expr, "checkpoint")
        && expression_mentions_ident(advanced_expr, "before")
        && tail.is_some_and(|tail| {
            expression_mentions_ident(tail, "run")
                && expression_mentions_ident(tail, "advanced")
                && contains_path_call(tail, "ProjectionAttemptObservation", "succeeded")
                && contains_path_call(tail, "ProjectionAttemptObservation", "failed")
        })
}

fn observation_flow_is_live(function: &syn::ItemFn) -> bool {
    store_local_observation_shape(function) || durable_owner_pool_observation_shape(function)
}

fn store_local_observation_shape(function: &syn::ItemFn) -> bool {
    let counts_from_store = function.block.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        let Some(init) = &local.init else {
            return false;
        };
        matches!(local.pat, syn::Pat::Tuple(_))
            && matches!(unwrap_expression(&init.expr), syn::Expr::MethodCall(call)
                if call.method == "counts" && expression_mentions_ident(&call.receiver, "store"))
    });
    counts_from_store
        && tail_expression(function).is_some_and(|tail| {
            contains_path_call(tail, "ProjectionObservation", "new")
                && ["attempts", "calls", "effects", "receipts"]
                    .iter()
                    .all(|ident| expression_mentions_ident(tail, ident))
        })
}

fn durable_owner_pool_observation_shape(function: &syn::ItemFn) -> bool {
    if function.sig.asyncness.is_none() {
        return false;
    }
    let Some(counts_call) = durable_conformance_counts_call(function) else {
        return false;
    };
    let params = function_param_idents(function);
    let Some(pool_owner) = pool_ref_param_ident(counts_call) else {
        return false;
    };
    if !params.contains(&pool_owner) {
        return false;
    }
    let Some(store_ident) = function_apply_calls_param_receiver(function, &params) else {
        return false;
    };
    pool_owner != store_ident
        && selector_tenant_and_version_same_binding(counts_call)
        && durable_observation_tail_is_live(function)
}

fn durable_conformance_counts_call(function: &syn::ItemFn) -> Option<&syn::ExprCall> {
    function.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        if !matches!(local.pat, syn::Pat::Tuple(_)) {
            return None;
        }
        let init = local.init.as_ref()?;
        find_awaited_suffix_call(&init.expr, "_conformance_counts")
    })
}

fn find_awaited_named_call<'a>(expression: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprCall> {
    find_awaited_call(expression, |call| {
        path_call_name(call).is_some_and(|ident| ident == name)
    })
}

fn find_awaited_suffix_call<'a>(
    expression: &'a syn::Expr,
    suffix: &str,
) -> Option<&'a syn::ExprCall> {
    find_awaited_call(expression, |call| {
        path_call_name(call).is_some_and(|ident| ident.ends_with(suffix))
    })
}

fn find_awaited_call(
    expression: &syn::Expr,
    predicate: impl Fn(&syn::ExprCall) -> bool + Copy,
) -> Option<&syn::ExprCall> {
    match expression {
        syn::Expr::Await(value) => match unwrap_expression(&value.base) {
            syn::Expr::Call(call) if predicate(call) => Some(call),
            other => find_awaited_call(other, predicate)
                .or_else(|| find_awaited_call(&value.base, predicate)),
        },
        syn::Expr::Try(value) => find_awaited_call(&value.expr, predicate),
        syn::Expr::MethodCall(value) => {
            find_awaited_call(&value.receiver, predicate).or_else(|| {
                value
                    .args
                    .iter()
                    .find_map(|argument| find_awaited_call(argument, predicate))
            })
        }
        syn::Expr::Call(value) => value
            .args
            .iter()
            .find_map(|argument| find_awaited_call(argument, predicate)),
        syn::Expr::Paren(value) => find_awaited_call(&value.expr, predicate),
        syn::Expr::Group(value) => find_awaited_call(&value.expr, predicate),
        syn::Expr::Cast(value) => find_awaited_call(&value.expr, predicate),
        _ => None,
    }
}

fn path_call_name(call: &syn::ExprCall) -> Option<String> {
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    function
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn pool_ref_param_ident(call: &syn::ExprCall) -> Option<String> {
    let expression = strip_group_paren(call.args.first()?);
    let syn::Expr::Reference(reference) = expression else {
        return None;
    };
    let field_expr = strip_group_paren(reference.expr.as_ref());
    let syn::Expr::Field(field) = field_expr else {
        return None;
    };
    if !matches!(&field.member, syn::Member::Named(name) if name == "pool") {
        return None;
    }
    path_single_ident(field.base.as_ref())
}

fn strip_group_paren(expression: &syn::Expr) -> &syn::Expr {
    match expression {
        syn::Expr::Group(value) => strip_group_paren(&value.expr),
        syn::Expr::Paren(value) => strip_group_paren(&value.expr),
        other => other,
    }
}

fn path_single_ident(expression: &syn::Expr) -> Option<String> {
    let expression = strip_group_paren(expression);
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    (path.path.segments.len() == 1).then(|| path.path.segments[0].ident.to_string())
}

fn function_param_idents(function: &syn::ItemFn) -> BTreeSet<String> {
    function
        .sig
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(typed) = input else {
                return None;
            };
            let syn::Pat::Ident(ident) = typed.pat.as_ref() else {
                return None;
            };
            Some(ident.ident.to_string())
        })
        .collect()
}

fn function_apply_calls_param_receiver(
    function: &syn::ItemFn,
    params: &BTreeSet<String>,
) -> Option<String> {
    function
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            syn::Stmt::Local(local) => local
                .init
                .as_ref()
                .and_then(|init| apply_calls_param_receiver(&init.expr, params)),
            syn::Stmt::Expr(expression, _) => apply_calls_param_receiver(expression, params),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
        })
}

fn apply_calls_param_receiver(expression: &syn::Expr, params: &BTreeSet<String>) -> Option<String> {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::MethodCall(call) => {
            if call.method == "apply_calls"
                && let Some(receiver) = path_single_ident(&call.receiver)
                && params.contains(&receiver)
            {
                return Some(receiver);
            }
            apply_calls_param_receiver(&call.receiver, params).or_else(|| {
                call.args
                    .iter()
                    .find_map(|argument| apply_calls_param_receiver(argument, params))
            })
        }
        syn::Expr::Call(call) => call
            .args
            .iter()
            .find_map(|argument| apply_calls_param_receiver(argument, params)),
        syn::Expr::Cast(cast) => apply_calls_param_receiver(&cast.expr, params),
        syn::Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .find_map(|element| apply_calls_param_receiver(element, params)),
        syn::Expr::Array(array) => array
            .elems
            .iter()
            .find_map(|element| apply_calls_param_receiver(element, params)),
        syn::Expr::If(value) => apply_calls_param_receiver(&value.cond, params)
            .or_else(|| {
                value
                    .then_branch
                    .stmts
                    .iter()
                    .find_map(|statement| match statement {
                        syn::Stmt::Local(local) => local
                            .init
                            .as_ref()
                            .and_then(|init| apply_calls_param_receiver(&init.expr, params)),
                        syn::Stmt::Expr(expression, _) => {
                            apply_calls_param_receiver(expression, params)
                        }
                        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
                    })
            })
            .or_else(|| {
                value
                    .else_branch
                    .as_ref()
                    .and_then(|(_, expression)| apply_calls_param_receiver(expression, params))
            }),
        _ => None,
    }
}

fn selector_tenant_and_version_same_binding(call: &syn::ExprCall) -> bool {
    let Some(tenant) = call.args.iter().nth(1) else {
        return false;
    };
    let Some(generation) = call.args.iter().nth(2) else {
        return false;
    };
    if is_string_literal(tenant) || is_string_literal(generation) {
        return false;
    }
    let Some(tenant_selector) = method_call_receiver_ident(tenant, "tenant") else {
        return false;
    };
    let Some(generation_selector) = selector_version_as_str_receiver(generation) else {
        return false;
    };
    tenant_selector == generation_selector
}

fn method_call_receiver_ident(expression: &syn::Expr, method: &str) -> Option<String> {
    let expression = strip_group_paren(expression);
    let syn::Expr::MethodCall(call) = expression else {
        return None;
    };
    (call.method == method)
        .then(|| path_single_ident(&call.receiver))
        .flatten()
}

fn selector_version_as_str_receiver(expression: &syn::Expr) -> Option<String> {
    let expression = strip_group_paren(expression);
    let syn::Expr::MethodCall(as_str) = expression else {
        return None;
    };
    if as_str.method != "as_str" {
        return None;
    }
    let version_expr = strip_group_paren(as_str.receiver.as_ref());
    let syn::Expr::MethodCall(version) = version_expr else {
        return None;
    };
    (version.method == "version")
        .then(|| path_single_ident(&version.receiver))
        .flatten()
}

fn is_string_literal(expression: &syn::Expr) -> bool {
    matches!(
        unwrap_expression(expression),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        })
    )
}

fn is_numeric_literal(expression: &syn::Expr) -> bool {
    matches!(
        unwrap_expression(expression),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(_),
            ..
        })
    )
}

fn contains_store_apply_calls(expression: &syn::Expr) -> bool {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::MethodCall(call) => {
            (call.method == "apply_calls" && path_single_ident(&call.receiver).is_some())
                || contains_store_apply_calls(&call.receiver)
                || call.args.iter().any(contains_store_apply_calls)
        }
        syn::Expr::Call(call) => call.args.iter().any(contains_store_apply_calls),
        syn::Expr::Cast(cast) => contains_store_apply_calls(&cast.expr),
        syn::Expr::Tuple(tuple) => tuple.elems.iter().any(contains_store_apply_calls),
        syn::Expr::Array(array) => array.elems.iter().any(contains_store_apply_calls),
        syn::Expr::If(value) => {
            contains_store_apply_calls(&value.cond)
                || value
                    .then_branch
                    .stmts
                    .iter()
                    .any(|statement| match statement {
                        syn::Stmt::Local(local) => local
                            .init
                            .as_ref()
                            .is_some_and(|init| contains_store_apply_calls(&init.expr)),
                        syn::Stmt::Expr(expression, _) => contains_store_apply_calls(expression),
                        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
                    })
                || value
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, expression)| contains_store_apply_calls(expression))
        }
        _ => false,
    }
}

fn durable_observation_tail_is_live(function: &syn::ItemFn) -> bool {
    let Some(tail) = tail_expression(function) else {
        return false;
    };
    let Some(call) = find_path_call(tail, "ProjectionObservation", "new") else {
        return false;
    };
    let args: Vec<_> = call.args.iter().collect();
    args.len() >= 4
        && expression_mentions_ident(args[0], "attempts")
        && !is_numeric_literal(args[1])
        && !is_numeric_literal(args[2])
        && !is_numeric_literal(args[3])
        && (expression_mentions_ident(args[1], "calls") || contains_store_apply_calls(args[1]))
        && expression_mentions_ident(args[2], "effects")
        && expression_mentions_ident(args[3], "receipts")
}

fn find_path_call<'a>(
    expression: &'a syn::Expr,
    owner: &str,
    method: &str,
) -> Option<&'a syn::ExprCall> {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::Call(call) => {
            let matches = match call.func.as_ref() {
                syn::Expr::Path(path) => {
                    let segments = path
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>();
                    segments.ends_with(&[owner.to_owned(), method.to_owned()])
                }
                _ => false,
            };
            if matches {
                Some(call)
            } else {
                call.args
                    .iter()
                    .find_map(|argument| find_path_call(argument, owner, method))
            }
        }
        syn::Expr::MethodCall(call) => {
            find_path_call(&call.receiver, owner, method).or_else(|| {
                call.args
                    .iter()
                    .find_map(|argument| find_path_call(argument, owner, method))
            })
        }
        syn::Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .find_map(|element| find_path_call(element, owner, method)),
        syn::Expr::Array(array) => array
            .elems
            .iter()
            .find_map(|element| find_path_call(element, owner, method)),
        _ => None,
    }
}

fn rollback_observation_flow_is_live(function: &syn::ItemFn) -> bool {
    staged_rollback_observation_shape(function) || durable_rollback_zero_shape(function)
}

fn staged_rollback_observation_shape(function: &syn::ItemFn) -> bool {
    let counts_from_store = function_has_store_transaction_counts(function);
    counts_from_store
        && function_has_lit_tuple_pair(function, 1, 1)
        && tail_expression(function).is_some_and(|tail| {
            path_call(tail, "observation").is_some()
                && expression_mentions_ident(tail, "attempts")
                && expression_mentions_ident(tail, "store")
        })
}

fn durable_rollback_zero_shape(function: &syn::ItemFn) -> bool {
    if function.sig.asyncness.is_none() {
        return false;
    }
    awaited_observation_with_store_owner(function)
        && observation_zero_check(function, "business_effects")
        && observation_zero_check(function, "receipts")
        && tail_expression(function)
            .is_some_and(|tail| expression_mentions_ident(tail, "observation"))
}

fn function_has_store_transaction_counts(function: &syn::ItemFn) -> bool {
    function.block.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        let Some(init) = &local.init else {
            return false;
        };
        contains_path_call(&init.expr, "store", "transaction_counts")
            || matches!(unwrap_expression(&init.expr), syn::Expr::MethodCall(call)
                if call.method == "transaction_counts"
                    && expression_mentions_ident(&call.receiver, "store"))
    })
}

fn function_has_lit_tuple_pair(function: &syn::ItemFn, left: u64, right: u64) -> bool {
    function
        .block
        .stmts
        .iter()
        .any(|statement| match statement {
            syn::Stmt::Local(local) => local
                .init
                .as_ref()
                .is_some_and(|init| expr_has_lit_tuple_pair(&init.expr, left, right)),
            syn::Stmt::Expr(expression, _) => expr_has_lit_tuple_pair(expression, left, right),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
        })
}

fn expr_has_lit_tuple_pair(expression: &syn::Expr, left: u64, right: u64) -> bool {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::Tuple(tuple) if tuple.elems.len() == 2 => {
            is_int_literal(&tuple.elems[0], left) && is_int_literal(&tuple.elems[1], right)
        }
        syn::Expr::Binary(binary) => {
            expr_has_lit_tuple_pair(&binary.left, left, right)
                || expr_has_lit_tuple_pair(&binary.right, left, right)
        }
        syn::Expr::If(value) => {
            expr_has_lit_tuple_pair(&value.cond, left, right)
                || value
                    .then_branch
                    .stmts
                    .iter()
                    .any(|statement| match statement {
                        syn::Stmt::Local(local) => local
                            .init
                            .as_ref()
                            .is_some_and(|init| expr_has_lit_tuple_pair(&init.expr, left, right)),
                        syn::Stmt::Expr(expression, _) => {
                            expr_has_lit_tuple_pair(expression, left, right)
                        }
                        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
                    })
                || value
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, expression)| expr_has_lit_tuple_pair(expression, left, right))
        }
        syn::Expr::Call(call) => call
            .args
            .iter()
            .any(|argument| expr_has_lit_tuple_pair(argument, left, right)),
        syn::Expr::MethodCall(call) => {
            expr_has_lit_tuple_pair(&call.receiver, left, right)
                || call
                    .args
                    .iter()
                    .any(|argument| expr_has_lit_tuple_pair(argument, left, right))
        }
        syn::Expr::Return(value) => value
            .expr
            .as_ref()
            .is_some_and(|expression| expr_has_lit_tuple_pair(expression, left, right)),
        _ => false,
    }
}

fn is_int_literal(expression: &syn::Expr, expected: u64) -> bool {
    matches!(
        unwrap_expression(expression),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) if value.base10_parse::<u64>().ok() == Some(expected)
    )
}

fn awaited_observation_with_store_owner(function: &syn::ItemFn) -> bool {
    function.block.stmts.iter().any(|statement| {
        let expression = match statement {
            syn::Stmt::Local(local) => local.init.as_ref().map(|init| init.expr.as_ref()),
            syn::Stmt::Expr(expression, _) => Some(expression),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
        };
        expression.is_some_and(|expression| {
            find_awaited_named_call(expression, "observation").is_some_and(|call| {
                call.args
                    .iter()
                    .any(|argument| expression_mentions_ident(argument, "store"))
                    && call
                        .args
                        .iter()
                        .any(|argument| expression_mentions_ident(argument, "owner"))
            })
        })
    })
}

fn observation_zero_check(function: &syn::ItemFn, method: &str) -> bool {
    function
        .block
        .stmts
        .iter()
        .any(|statement| match statement {
            syn::Stmt::Local(local) => local
                .init
                .as_ref()
                .is_some_and(|init| expr_observation_zero_check(&init.expr, method)),
            syn::Stmt::Expr(expression, _) => expr_observation_zero_check(expression, method),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
        })
}

fn expr_observation_zero_check(expression: &syn::Expr, method: &str) -> bool {
    let expression = unwrap_expression(expression);
    match expression {
        syn::Expr::Binary(binary) => {
            method_compared_to_zero(&binary.left, &binary.right, method)
                || method_compared_to_zero(&binary.right, &binary.left, method)
                || expr_observation_zero_check(&binary.left, method)
                || expr_observation_zero_check(&binary.right, method)
        }
        syn::Expr::If(value) => {
            expr_observation_zero_check(&value.cond, method)
                || value
                    .then_branch
                    .stmts
                    .iter()
                    .any(|statement| match statement {
                        syn::Stmt::Local(local) => local
                            .init
                            .as_ref()
                            .is_some_and(|init| expr_observation_zero_check(&init.expr, method)),
                        syn::Stmt::Expr(expression, _) => {
                            expr_observation_zero_check(expression, method)
                        }
                        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
                    })
                || value
                    .else_branch
                    .as_ref()
                    .is_some_and(|(_, expression)| expr_observation_zero_check(expression, method))
        }
        syn::Expr::Unary(value) => expr_observation_zero_check(&value.expr, method),
        syn::Expr::Paren(value) => expr_observation_zero_check(&value.expr, method),
        syn::Expr::Group(value) => expr_observation_zero_check(&value.expr, method),
        syn::Expr::MethodCall(call) => {
            expr_observation_zero_check(&call.receiver, method)
                || call
                    .args
                    .iter()
                    .any(|argument| expr_observation_zero_check(argument, method))
        }
        syn::Expr::Call(call) => call
            .args
            .iter()
            .any(|argument| expr_observation_zero_check(argument, method)),
        _ => false,
    }
}

fn method_compared_to_zero(method_side: &syn::Expr, zero_side: &syn::Expr, method: &str) -> bool {
    is_int_literal(zero_side, 0)
        && matches!(
            unwrap_expression(method_side),
            syn::Expr::MethodCall(call)
                if call.method == method
                    && expression_mentions_ident(&call.receiver, "observation")
        )
}

fn resolved_behavior_is_live(
    function: &syn::ItemFn,
    functions: &BTreeMap<String, Vec<syn::ItemFn>>,
) -> bool {
    if behavior_flow_is_live(function) {
        return true;
    }
    let Some(tail) = tail_expression(function) else {
        return false;
    };
    let Some(call) = (match unwrap_expression(tail) {
        syn::Expr::Call(call) => Some(call),
        _ => None,
    }) else {
        return false;
    };
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return false;
    };
    let Some(helper) = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return false;
    };
    helper.ends_with("_with")
        && unique_function(functions, &helper).is_some_and(behavior_flow_is_live)
}

fn behavior_flow_is_live(function: &syn::ItemFn) -> bool {
    if function.sig.asyncness.is_none() {
        return false;
    }
    let mut attempt_bindings = Vec::new();
    for (binding, expression) in direct_locals(function) {
        if !matches!(expression, syn::Expr::Await(_)) {
            continue;
        }
        let Some(call) = path_call(expression, "attempt") else {
            continue;
        };
        let has_target = call
            .args
            .iter()
            .any(|argument| path_call(argument, "target").is_some());
        let has_checkpoint = call.args.iter().any(|argument| {
            expression_mentions_ident(argument, "checkpoint")
                || contains_path_call(argument, "CheckpointStore", "default")
        });
        if !has_target || !has_checkpoint {
            return false;
        }
        attempt_bindings.push(binding);
    }
    let Some(tail) = tail_expression(function) else {
        return false;
    };
    let observation =
        path_call(tail, "observation").or_else(|| path_call(tail, "rollback_observation"));
    let Some(observation) = observation else {
        return false;
    };
    let Some(attempts) = observation.args.first() else {
        return false;
    };
    !attempt_bindings.is_empty()
        && expression_mentions_ident(tail, "store")
        && attempt_bindings
            .iter()
            .all(|binding| expression_mentions_ident(attempts, binding))
}

fn runtime_funnel_findings(root: &Path, packages: &[Package]) -> Result<Vec<Finding<Rule>>> {
    let mut inventory = RuntimeFunnelInventory::default();
    for package in packages {
        for source in &package.production_sources {
            let relative = relative_string(root, source);
            let file = parse_file(source)?;
            let mut visitor = RuntimeFunnelVisitor::new(relative);
            visitor.visit_file(&file);
            inventory.merge(visitor.inventory);
        }
    }
    let mut findings = Vec::new();
    let owner = EVENTEXEC_PROJECTION_OWNER;
    if inventory.target_impls != [(owner.to_owned(), "ConformingProjectionTarget".to_owned())] {
        findings.push(finding(
            Rule::ForbiddenWiring,
            owner,
            format!(
                "predicate=projection_target_sealed_impl: ProjectionTarget impl set must be exactly ConformingProjectionTarget in the canonical owner, got {:?}",
                inventory.target_impls
            ),
        ));
    }
    if inventory.target_traits != 1
        || inventory.sealed_target_traits != 1
        || inventory.sealed_wrapper_impls != 1
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            owner,
            format!(
                "predicate=projection_target_sealed_shape: expected exactly one target trait, sealed once, and one wrapper seal impl; got traits={} sealed_traits={} seals={}",
                inventory.target_traits,
                inventory.sealed_target_traits,
                inventory.sealed_wrapper_impls
            ),
        ));
    }
    if inventory.validated_structs != 1
        || inventory.validated_fields_private != 1
        || inventory.validated_constructions
            != [(owner.to_owned(), "ConformingProjectionTarget".to_owned())]
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            owner,
            format!(
                "predicate=projection_target_private_input: validated input must have one private-field declaration and one construction inside ConformingProjectionTarget, got declarations={} private={} constructions={:?}",
                inventory.validated_structs,
                inventory.validated_fields_private,
                inventory.validated_constructions
            ),
        ));
    }
    for (path, ident) in inventory.legacy_idents {
        findings.push(finding(
            Rule::ForbiddenWiring,
            path,
            format!("predicate=projection_target_no_legacy: production source revives `{ident}`"),
        ));
    }
    for path in inventory.protected_macro_bypasses {
        findings.push(finding(
            Rule::ForbiddenWiring,
            path,
            "predicate=projection_target_macro_bypass: protected target impl/input seams cannot be hidden in production macros",
        ));
    }
    Ok(findings)
}

fn disabled_activation_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let canonical_root = fs::canonicalize(root)
        .with_context(|| format!("canonicalize repository root {}", root.display()))?;
    let governance = crate::assembly_governance::AssemblyGovernanceIr::<
        crate::assembly_governance::Core,
    >::load(&canonical_root)?;
    let mut findings = Vec::new();
    for assembly in governance.assemblies() {
        for activation in assembly.manifest().workflow_activations() {
            if let assembly_schema::WorkflowActivation::Projection {
                activation: state, ..
            } = activation
                && *state != assembly_schema::ProjectionActivation::Disabled
            {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    assembly.manifest_label(),
                    format!(
                        "predicate=projection_target_empty_inventory_disabled: production store inventory is empty but projection activation is {state:?}"
                    ),
                ));
            }
        }
    }
    Ok(findings)
}

fn packages(root: &Path) -> Result<Vec<Package>> {
    let workspace_text = fs::read_to_string(root.join("Cargo.toml"))?;
    let workspace: toml::Value = toml::from_str(&workspace_text)?;
    let members = workspace
        .get("workspace")
        .and_then(|value| value.get("members"))
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let excludes = workspace
        .get("workspace")
        .and_then(|value| value.get("exclude"))
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let relative_members = workspace_member_paths(root, members, excludes)?;
    let mut packages = Vec::new();
    for relative in relative_members {
        let manifest_path = root.join(&relative).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(&manifest_path)?)?;
        let name = manifest
            .get("package")
            .and_then(|value| value.get("name"))
            .and_then(toml::Value::as_str)
            .with_context(|| format!("package.name missing in {}", manifest_path.display()))?
            .to_owned();
        let package_root = root.join(&relative);
        let mut all_sources = BTreeSet::new();
        for source_dir in ["src", "tests", "examples", "benches"] {
            collect_rs(&package_root.join(source_dir), &mut all_sources)?;
        }
        let target_inventory = crate::archrules::cargo_target_inventory(
            &package_root,
            &package_root.join("Cargo.toml"),
        )?;
        for target in &target_inventory {
            all_sources.insert(target.path.clone());
            if let Some(parent) = target.path.parent() {
                collect_rs(parent, &mut all_sources)?;
            }
        }
        let mut test_sources = BTreeSet::new();
        let mut test_target_sources = BTreeMap::new();
        for target in &target_inventory {
            if matches!(
                target.class,
                crate::archrules::CargoTargetClass::Lib | crate::archrules::CargoTargetClass::Test
            ) {
                let reachable = crate::archrules::cargo_target_reachable_files(target)?;
                test_sources.extend(reachable.iter().cloned());
                test_target_sources.insert(target.path.clone(), reachable);
            }
        }
        let roots = target_inventory
            .into_iter()
            .map(|target| (target.path, target.class.is_production_scan()))
            .collect();
        let (tracked_sources, production_sources) = module_sources(&all_sources, roots)?;
        packages.push(Package {
            name,
            relative,
            all_sources,
            tracked_sources,
            production_sources,
            test_sources,
            test_target_sources,
        });
    }
    Ok(packages)
}

fn workspace_member_paths(
    root: &Path,
    members: &[toml::Value],
    excludes: &[toml::Value],
) -> Result<Vec<PathBuf>> {
    let patterns = members
        .iter()
        .map(|member| {
            member
                .as_str()
                .map(str::to_owned)
                .context("workspace member must be string")
        })
        .collect::<Result<Vec<_>>>()?;
    let excludes = excludes
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    let mut manifests = Vec::new();
    for pattern in &patterns {
        let prefix = pattern
            .split('/')
            .take_while(|component| !component.contains(['*', '?']))
            .collect::<PathBuf>();
        if prefix == Path::new("assemblies") || prefix.as_os_str().is_empty() {
            for target in crate::assembly_governance::discover_targets(root)? {
                if target.has_cargo_manifest() {
                    manifests.push(target.cargo_path());
                }
            }
        }
        if prefix == Path::new("assemblies") {
            continue;
        }
        if prefix.as_os_str().is_empty() {
            for entry in fs::read_dir(root)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() || entry.file_name() == "assemblies" {
                    continue;
                }
                collect_package_manifests(&entry.path(), &mut manifests)?;
            }
        } else {
            collect_package_manifests(&root.join(prefix), &mut manifests)?;
        }
    }
    let mut paths = manifests
        .into_iter()
        .filter_map(|manifest| manifest.parent().map(Path::to_path_buf))
        .filter_map(|package_root| package_root.strip_prefix(root).ok().map(Path::to_path_buf))
        .filter(|relative| {
            let candidate = relative.to_string_lossy().replace('\\', "/");
            patterns
                .iter()
                .any(|pattern| glob_path_matches(pattern, &candidate))
                && !excludes
                    .iter()
                    .any(|pattern| glob_path_matches(pattern, &candidate))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect_package_manifests(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let manifest = dir.join("Cargo.toml");
    if manifest.is_file() {
        out.push(manifest);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || matches!(
                entry.file_name().to_str(),
                Some(".git" | "target" | "worktrees")
            )
        {
            continue;
        }
        collect_package_manifests(&entry.path(), out)?;
    }
    Ok(())
}

fn glob_path_matches(pattern: &str, candidate: &str) -> bool {
    fn components(pattern: &[&str], candidate: &[&str]) -> bool {
        match (pattern.split_first(), candidate.split_first()) {
            (None, None) => true,
            (Some((&"**", rest)), _) => {
                components(rest, candidate)
                    || candidate
                        .split_first()
                        .is_some_and(|(_, tail)| components(pattern, tail))
            }
            (Some((head, rest)), Some((value, tail))) => {
                component_matches(head, value) && components(rest, tail)
            }
            _ => false,
        }
    }

    fn component_matches(pattern: &str, value: &str) -> bool {
        let mut reachable = vec![false; value.len() + 1];
        reachable[0] = true;
        for token in pattern.as_bytes() {
            let mut next = vec![false; value.len() + 1];
            match token {
                b'*' => {
                    let mut seen = false;
                    for index in 0..=value.len() {
                        seen |= reachable[index];
                        next[index] = seen;
                    }
                }
                b'?' => {
                    for index in 0..value.len() {
                        next[index + 1] |= reachable[index];
                    }
                }
                literal => {
                    for (index, byte) in value.as_bytes().iter().enumerate() {
                        next[index + 1] |= reachable[index] && byte == literal;
                    }
                }
            }
            reachable = next;
        }
        reachable[value.len()]
    }

    let pattern = pattern.trim_matches('/').split('/').collect::<Vec<_>>();
    let candidate = candidate.trim_matches('/').split('/').collect::<Vec<_>>();
    components(&pattern, &candidate)
}

fn module_sources(
    sources: &BTreeSet<PathBuf>,
    roots: Vec<(PathBuf, bool)>,
) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>)> {
    let mut tracked = BTreeSet::new();
    let mut production = BTreeSet::new();
    let mut queue = roots
        .into_iter()
        .filter(|(path, _)| sources.contains(path))
        .collect::<VecDeque<_>>();
    while let Some((path, is_production)) = queue.pop_front() {
        let first = tracked.insert(path.clone());
        if is_production {
            production.insert(path.clone());
        }
        if !first && !is_production {
            continue;
        }
        let file = parse_file(&path)?;
        let base = module_base(&path);
        collect_module_targets(&file.items, &base, is_production, sources, &mut queue);
    }
    Ok((tracked, production))
}

fn collect_module_targets(
    items: &[syn::Item],
    base: &Path,
    parent_production: bool,
    sources: &BTreeSet<PathBuf>,
    queue: &mut VecDeque<(PathBuf, bool)>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let production = parent_production && attrs_may_be_production(&module.attrs);
        if let Some((_, nested)) = &module.content {
            collect_module_targets(
                nested,
                &base.join(module.ident.to_string()),
                production,
                sources,
                queue,
            );
            continue;
        }
        if let Some(path) = module.attrs.iter().find_map(|attribute| {
            if !attribute.path().is_ident("path") {
                return None;
            }
            let syn::Meta::NameValue(value) = &attribute.meta else {
                return None;
            };
            let syn::Expr::Lit(value) = &value.value else {
                return None;
            };
            let syn::Lit::Str(value) = &value.lit else {
                return None;
            };
            let direct = base.join(value.value());
            let sibling = base.parent().unwrap_or(base).join(value.value());
            Some(if sources.contains(&direct) {
                direct
            } else {
                sibling
            })
        }) {
            if sources.contains(&path) {
                queue.push_back((path, production));
            }
            continue;
        }
        let candidates = [
            base.join(format!("{}.rs", module.ident)),
            base.join(module.ident.to_string()).join("mod.rs"),
        ];
        if let Some(path) = candidates.into_iter().find(|path| sources.contains(path)) {
            queue.push_back((path, production));
        }
    }
}

fn module_base(path: &Path) -> PathBuf {
    match path.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") => path.parent().unwrap_or(Path::new("")).to_owned(),
        Some(stem) => path.parent().unwrap_or(Path::new("")).join(stem),
        None => path.parent().unwrap_or(Path::new("")).to_owned(),
    }
}

fn package_enrollments(package: &Package) -> Result<Vec<Enrollment>> {
    let mut enrollments = Vec::new();
    for source in &package.all_sources {
        let file = parse_file(source)?;
        let mut visitor = EnrollmentVisitor {
            source: source.clone(),
            enrollments: Vec::new(),
            statically_disabled: false,
        };
        visitor.visit_file(&file);
        enrollments.extend(visitor.enrollments);
    }
    Ok(enrollments)
}

fn reachable_test_source(package: &Package, source: &Path) -> bool {
    package.test_sources.contains(source)
        && package
            .test_target_sources
            .values()
            .filter(|sources| sources.contains(source))
            .count()
            == 1
}

fn package_functions(
    package: &Package,
    enrollment_source: &Path,
) -> Result<BTreeMap<String, Vec<syn::ItemFn>>> {
    let mut functions: BTreeMap<String, Vec<syn::ItemFn>> = BTreeMap::new();
    let Some((_, target_sources)) = package
        .test_target_sources
        .iter()
        .find(|(_, sources)| sources.contains(enrollment_source))
    else {
        return Ok(functions);
    };
    for source in target_sources {
        let file = parse_file(source)?;
        let mut visitor = FunctionVisitor::default();
        visitor.visit_file(&file);
        for function in visitor.functions {
            functions
                .entry(function.sig.ident.to_string())
                .or_default()
                .push(function);
        }
    }
    Ok(functions)
}

fn collect_rs(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.insert(path);
        }
    }
    Ok(())
}

fn parse_file(path: &Path) -> Result<syn::File> {
    syn::parse_file(&fs::read_to_string(path)?)
        .with_context(|| format!("parse projection target source {}", path.display()))
}

fn relative_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn compact<T: ToTokens>(value: &T) -> String {
    value.to_token_stream().to_string().replace(' ', "")
}

fn last_ident(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
        _ => compact(ty),
    }
}

struct OpaqueCodegenVisitor<'a> {
    source: &'a str,
    production: bool,
    opaque: Vec<String>,
}

impl Visit<'_> for OpaqueCodegenVisitor<'_> {
    fn visit_item_mod(&mut self, node: &syn::ItemMod) {
        let was = self.production;
        self.production = self.production && attrs_may_be_production(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.production = was;
    }

    fn visit_item_macro(&mut self, node: &syn::ItemMacro) {
        if self.production {
            let name = node
                .ident
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| {
                    node.mac
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                })
                .unwrap_or_else(|| "<anonymous>".to_owned());
            if !allowed_item_macro(self.source, &name, node) {
                self.opaque.push(format!("item-macro:{name}"));
            }
        }
        syn::visit::visit_item_macro(self, node);
    }

    fn visit_attribute(&mut self, node: &syn::Attribute) {
        if self.production {
            self.inspect_attributes(std::slice::from_ref(node));
        }
        syn::visit::visit_attribute(self, node);
    }
}

impl OpaqueCodegenVisitor<'_> {
    fn inspect_attributes(&mut self, attributes: &[syn::Attribute]) {
        if !self.production {
            return;
        }
        for attribute in attributes {
            let path = attribute
                .path()
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            if path == ["derive"] {
                let Ok(derives) = attribute.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                ) else {
                    self.opaque.push("derive:<unparseable>".to_owned());
                    continue;
                };
                for derive in derives {
                    let name = derive
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                        .unwrap_or_default();
                    if !ALLOWED_DERIVES.contains(&name.as_str()) {
                        self.opaque.push(format!("derive:{name}"));
                    }
                }
            } else if path == ["cfg_attr"] {
                let Ok(items) = attribute.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                ) else {
                    self.opaque
                        .push("attribute:cfg_attr:<unparseable>".to_owned());
                    continue;
                };
                for meta in items.iter().skip(1) {
                    self.inspect_cfg_attr_meta(meta);
                }
            } else {
                let full = path.join("::");
                if !ALLOWED_ATTRIBUTES.contains(&full.as_str()) {
                    self.opaque.push(format!("attribute:{full}"));
                }
            }
        }
    }

    fn inspect_cfg_attr_meta(&mut self, meta: &syn::Meta) {
        let path = meta
            .path()
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let full = path.join("::");
        if full == "derive" {
            let syn::Meta::List(list) = meta else {
                self.opaque.push("derive:<invalid>".to_owned());
                return;
            };
            let Ok(derives) =
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                self.opaque.push("derive:<unparseable>".to_owned());
                return;
            };
            for derive in derives {
                let name = derive
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                if !ALLOWED_DERIVES.contains(&name.as_str()) {
                    self.opaque.push(format!("derive:{name}"));
                }
            }
        } else if !ALLOWED_ATTRIBUTES.contains(&full.as_str()) {
            self.opaque.push(format!("attribute:{full}"));
        }
    }
}

const ALLOWED_DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Deserialize",
    "Eq",
    "Error",
    "FromRow",
    "Hash",
    "JsonSchema",
    "Ord",
    "PartialEq",
    "PartialOrd",
    "Serialize",
    "Redact",
    "ZeroizeOnDrop",
];

const ALLOWED_ATTRIBUTES: &[&str] = &[
    "allow",
    "cfg",
    "cold",
    "deprecated",
    "deny",
    "doc",
    "error",
    "forbid",
    "from",
    "inline",
    "must_use",
    "non_exhaustive",
    "path",
    "redact",
    "repr",
    "schemars",
    "serde",
    "source",
    "tracing::instrument",
    "trait_variant::make",
    "dynosaur",
    "warn",
];

fn allowed_item_macro(source: &str, name: &str, item: &syn::ItemMacro) -> bool {
    let explicitly_owned = matches!(
        (source, name),
        (
            "crates/eventexec/src/managed_blocking_worker.rs",
            "thread_local"
        ) | ("crates/eventexec/src/relay.rs", "adopt_worker")
            | ("adapters/postgres/src/tx_retry.rs", "deadline_evidence")
            | ("adapters/postgres/src/tx_retry.rs", "task_local")
            | ("adapters/postgres/src/cotx/mod.rs", "task_local")
            | ("assemblies/settingsonly/src/config.rs", "dlx_postgres_role")
            | (
                "assemblies/runtime/src/provider_output.rs",
                "provider_permits"
            )
            | ("assemblies/runtime/src/infra/pg.rs", "role_builder")
            | ("assemblies/identityaudit/src/config.rs", "postgres_role")
            | ("assemblies/settingsonly/src/providers.rs", "batch")
            | ("crates/identity/src/ports.rs", "classify_identity_ports")
    );
    let shape = compact(&item.mac);
    explicitly_owned
        && ![
            "ProjectionTargetStore",
            "ProjectionTarget",
            "ValidatedProjectionApply",
        ]
        .iter()
        .any(|protected| shape.contains(protected))
}

struct ProductionImplVisitor {
    production: bool,
    store_impls: Vec<String>,
    store_macro_bypasses: usize,
    store_alias_bypasses: usize,
}

fn attrs_may_be_projection_production(attrs: &[syn::Attribute]) -> bool {
    attrs_may_be_production(attrs)
        && !attrs.iter().any(|attribute| {
            attribute.path().is_ident("cfg")
                && compact(attribute).contains("feature=\"test-support\"")
        })
}

impl Default for ProductionImplVisitor {
    fn default() -> Self {
        Self {
            production: true,
            store_impls: Vec::new(),
            store_macro_bypasses: 0,
            store_alias_bypasses: 0,
        }
    }
}

impl<'ast> Visit<'ast> for ProductionImplVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let was = self.production;
        self.production = self.production && attrs_may_be_projection_production(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.production = was;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if self.production
            && attrs_may_be_projection_production(&node.attrs)
            && node
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .is_some_and(|segment| segment.ident == "ProjectionTargetStore")
        {
            self.store_impls.push(last_ident(&node.self_ty));
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.production && macro_mentions_store_impl(&node.tokens) {
            self.store_macro_bypasses += 1;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_use_rename(&mut self, node: &'ast syn::UseRename) {
        if self.production && node.ident == "ProjectionTargetStore" {
            self.store_alias_bypasses += 1;
        }
        syn::visit::visit_use_rename(self, node);
    }
}

fn macro_mentions_store_impl(tokens: &proc_macro2::TokenStream) -> bool {
    fn identifiers(tokens: &proc_macro2::TokenStream, output: &mut Vec<String>) {
        for token in tokens.clone() {
            match token {
                proc_macro2::TokenTree::Ident(ident) => output.push(ident.to_string()),
                proc_macro2::TokenTree::Group(group) => identifiers(&group.stream(), output),
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
    let mut idents = Vec::new();
    identifiers(tokens, &mut idents);
    idents
        .iter()
        .position(|ident| ident == "impl")
        .is_some_and(|position| {
            idents[position + 1..]
                .iter()
                .any(|ident| ident == "ProjectionTargetStore")
        })
}

struct EnrollmentArgs {
    cases: Vec<EnrollmentCase>,
}

impl Parse for EnrollmentArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let keyword: syn::Ident = input.parse()?;
        if keyword != "cases" {
            return Err(syn::Error::new(keyword.span(), "expected `cases`"));
        }
        input.parse::<syn::Token![:]>()?;
        let content;
        syn::braced!(content in input);
        let mut cases = Vec::new();
        while !content.is_empty() {
            let case: syn::Ident = content.parse()?;
            content.parse::<syn::Token![=>]>()?;
            let body;
            syn::braced!(body in content);
            let test_attributes = body.call(syn::Attribute::parse_outer)?;
            let runner: syn::Ident = body.parse()?;
            body.parse::<syn::Token![=>]>()?;
            let behavior: syn::Path = body.parse()?;
            if !body.is_empty() {
                return Err(body.error("unexpected enrollment case tokens"));
            }
            cases.push(EnrollmentCase {
                case: case.to_string(),
                runner: runner.to_string(),
                behavior: compact(&behavior).replace(' ', ""),
                test_attributes,
            });
            if content.peek(syn::Token![,]) {
                content.parse::<syn::Token![,]>()?;
            }
        }
        Ok(Self { cases })
    }
}

struct EnrollmentVisitor {
    source: PathBuf,
    enrollments: Vec<Enrollment>,
    statically_disabled: bool,
}

impl<'ast> Visit<'ast> for EnrollmentVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let was = self.statically_disabled;
        self.statically_disabled =
            self.statically_disabled || crate::archrules::attrs_statically_disabled(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.statically_disabled = was;
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node
            .mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "projection_target_conformance")
        {
            let disabled = self.statically_disabled
                || crate::archrules::attrs_statically_disabled(&node.attrs);
            match syn::parse2::<EnrollmentArgs>(node.mac.tokens.clone()) {
                Ok(args) => self.enrollments.push(Enrollment {
                    source: self.source.clone(),
                    cases: args.cases,
                    parse_error: None,
                    statically_disabled: disabled,
                }),
                Err(error) => self.enrollments.push(Enrollment {
                    source: self.source.clone(),
                    cases: Vec::new(),
                    parse_error: Some(error.to_string()),
                    statically_disabled: disabled,
                }),
            }
        }
        syn::visit::visit_item_macro(self, node);
    }
}

#[derive(Default)]
struct FunctionVisitor {
    functions: Vec<syn::ItemFn>,
}

impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.functions.push(node.clone());
        syn::visit::visit_item_fn(self, node);
    }
}

#[derive(Default)]
struct RuntimeFunnelInventory {
    target_impls: Vec<(String, String)>,
    target_traits: usize,
    sealed_target_traits: usize,
    sealed_wrapper_impls: usize,
    validated_structs: usize,
    validated_fields_private: usize,
    validated_constructions: Vec<(String, String)>,
    legacy_idents: Vec<(String, String)>,
    protected_macro_bypasses: Vec<String>,
}

impl RuntimeFunnelInventory {
    fn merge(&mut self, other: Self) {
        self.target_impls.extend(other.target_impls);
        self.target_traits += other.target_traits;
        self.sealed_target_traits += other.sealed_target_traits;
        self.sealed_wrapper_impls += other.sealed_wrapper_impls;
        self.validated_structs += other.validated_structs;
        self.validated_fields_private += other.validated_fields_private;
        self.validated_constructions
            .extend(other.validated_constructions);
        self.legacy_idents.extend(other.legacy_idents);
        self.protected_macro_bypasses
            .extend(other.protected_macro_bypasses);
    }
}

struct RuntimeFunnelVisitor {
    source: String,
    production: bool,
    current_impl: Option<String>,
    inventory: RuntimeFunnelInventory,
}

impl RuntimeFunnelVisitor {
    fn new(source: String) -> Self {
        Self {
            source,
            production: true,
            current_impl: None,
            inventory: RuntimeFunnelInventory::default(),
        }
    }
}

impl<'ast> Visit<'ast> for RuntimeFunnelVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let was = self.production;
        self.production = self.production && attrs_may_be_production(&node.attrs);
        syn::visit::visit_item_mod(self, node);
        self.production = was;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if self.production && node.ident == "ProjectionTarget" {
            self.inventory.target_traits += 1;
            let sealed = node.supertraits.iter().any(|bound| {
                matches!(bound, syn::TypeParamBound::Trait(bound)
                    if bound.path.segments.last().is_some_and(|segment| segment.ident == "Sealed"))
            });
            self.inventory.sealed_target_traits += usize::from(sealed);
        }
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let was = self.current_impl.take();
        let owner = last_ident(&node.self_ty);
        self.current_impl = Some(owner.clone());
        if self.production && attrs_may_be_production(&node.attrs) {
            let trait_name = node
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .map(|segment| segment.ident.to_string());
            if trait_name.as_deref() == Some("ProjectionTarget") {
                self.inventory
                    .target_impls
                    .push((self.source.clone(), owner.clone()));
            }
            if trait_name.as_deref() == Some("Sealed") && owner == "ConformingProjectionTarget" {
                self.inventory.sealed_wrapper_impls += 1;
            }
        }
        syn::visit::visit_item_impl(self, node);
        self.current_impl = was;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if self.production && node.ident == "ValidatedProjectionApply" {
            self.inventory.validated_structs += 1;
            if node
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
            {
                self.inventory.validated_fields_private += 1;
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if self.production
            && node
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "ValidatedProjectionApply")
        {
            self.inventory.validated_constructions.push((
                self.source.clone(),
                self.current_impl
                    .clone()
                    .unwrap_or_else(|| "<free>".to_owned()),
            ));
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        if self.production {
            let ident = node.to_string();
            if LEGACY_IDENTS.contains(&ident.as_str()) {
                self.inventory
                    .legacy_idents
                    .push((self.source.clone(), ident));
            }
        }
        syn::visit::visit_ident(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.production {
            let shape = compact(node);
            if shape.contains("ValidatedProjectionApply")
                || shape.contains("implProjectionTarget")
                || LEGACY_IDENTS.iter().any(|ident| shape.contains(ident))
            {
                self.inventory
                    .protected_macro_bypasses
                    .push(self.source.clone());
            }
        }
        syn::visit::visit_macro(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;

    fn write(path: &Path, text: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn workspace(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        populate_workspace(&root)?;
        Ok(root)
    }

    fn populate_workspace(root: &Path) -> Result<()> {
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"adapters/demo\", \"crates/eventexec\"]\n",
        )?;
        write(
            &root.join("adapters/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n",
        )?;
        write(
            &root.join("crates/eventexec/Cargo.toml"),
            "[package]\nname = \"eventexec\"\nversion = \"0.0.0\"\n",
        )?;
        write(
            &root.join(EVENTEXEC_PROJECTION_OWNER),
            canonical_runtime_owner(),
        )?;
        write(
            &root.join(PROJECTION_CATALOG_OWNER),
            projection_catalog_fixture(),
        )?;
        write(
            &root.join("crates/eventexec/tests/projection_target_conformance.rs"),
            &canonical_enrollment(root)?,
        )?;
        Ok(())
    }

    fn projection_catalog_fixture() -> &'static str {
        r#"
pub enum ProjectionCase {
    AtomicApply,
    SameFactDuplicate,
    SameKeyConflict,
    PersistentOutOfOrder,
    IdentityMismatch,
    ConfirmedRollback,
    CommitUnknownReplay,
    RollbackFailed,
}
impl ProjectionCase {
    pub const ALL: [Self; 8] = [
        Self::AtomicApply,
        Self::SameFactDuplicate,
        Self::SameKeyConflict,
        Self::PersistentOutOfOrder,
        Self::IdentityMismatch,
        Self::ConfirmedRollback,
        Self::CommitUnknownReplay,
        Self::RollbackFailed,
    ];
}
"#
    }

    fn canonical_runtime_owner() -> &'static str {
        r#"
mod target_sealed { pub trait Sealed {} }
pub trait ProjectionTarget: target_sealed::Sealed {}
pub struct ValidatedProjectionApply { value: u64 }
pub struct ConformingProjectionTarget;
impl target_sealed::Sealed for ConformingProjectionTarget {}
impl ProjectionTarget for ConformingProjectionTarget {}
impl ConformingProjectionTarget {
    fn validate() -> ValidatedProjectionApply { ValidatedProjectionApply { value: 1 } }
}
"#
    }

    fn store_source() -> &'static str {
        "pub struct DemoStore;\nimpl ProjectionTargetStore for DemoStore {}\n"
    }

    fn canonical_enrollment(root: &Path) -> Result<String> {
        let canonical_cases = canonical_cases(root)?;
        let cases = canonical_cases
            .iter()
            .map(|case| format!("{case} => {{ #[tokio::test] run_{case} => behavior_{case} }}"))
            .collect::<Vec<_>>()
            .join(",\n");
        let behaviors = canonical_cases
            .iter()
            .map(|case| canonical_behavior(case))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!(
            r#"
fn target(store: DemoStore) -> Target {{
    Arc::new(ConformingProjectionTarget::new(store))
}}
async fn attempt(target: Target, checkpoint: Checkpoint) -> Attempt {{
    let before = checkpoint.offset();
    let selector = selector();
    let execution = WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
        selector.projection(),
        selector.tenant(),
    ).expect("generated projection execution");
    let harness = ProjectionHarness::new(
        ProjectionProjector::with_execution(execution, selector, target)
            .expect("plan-issued execution matches selector"),
        checkpoint.clone(),
    );
    let run = harness.run(&events()).await;
    let advanced = checkpoint.offset() != before;
    if run.applied == 1 {{
        ProjectionAttemptObservation::succeeded(Applied, advanced)
    }} else {{
        ProjectionAttemptObservation::failed(Permanent)
    }}
}}
fn observation(attempts: Vec<Attempt>, store: &DemoStore) -> Result<ProjectionObservation, Error> {{
    let (calls, effects, receipts) = store.counts();
    Ok(ProjectionObservation::new(attempts, calls, effects, receipts))
}}
{behaviors}
testkit::projection_target_conformance! {{ cases: {{ {cases}, }} }}
"#
        ))
    }

    fn canonical_behavior(case: &str) -> String {
        format!(
            r#"async fn behavior_{case}() -> Result<ProjectionObservation, Error> {{
    let store = DemoStore::new();
    let checkpoint = Checkpoint::new();
    let result = attempt(target(store.clone()), checkpoint, event()).await;
    observation(vec![result], &store)
}}"#
        )
    }

    fn durable_observation_fn() -> &'static str {
        r#"async fn observation(attempts: Vec<Attempt>, store: &DemoStore, owner: &Owner) -> Result<ProjectionObservation, Error> {
    let selector = demo_conformance_selector();
    let (effects, receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    ).await?;
    Ok(ProjectionObservation::new(attempts, store.apply_calls(), effects, receipts))
}
async fn rollback_observation(attempts: Vec<Attempt>, store: &DemoStore, owner: &Owner) -> Result<ProjectionObservation, Error> {
    let observation = observation(attempts, store, owner).await?;
    if observation.business_effects() != 0 || observation.receipts() != 0 {
        return Err(Error::Mismatch);
    }
    Ok(observation)
}"#
    }

    fn durable_behavior(case: &str) -> String {
        format!(
            r#"async fn behavior_{case}() -> Result<ProjectionObservation, Error> {{
    let store = DemoStore::new();
    let owner = Owner::new();
    let checkpoint = Checkpoint::new();
    let result = attempt(target(store.clone()), checkpoint, event()).await;
    observation(vec![result], &store, &owner).await
}}"#
        )
    }

    fn durable_enrollment(root: &Path) -> Result<String> {
        let canonical_cases = canonical_cases(root)?;
        let cases = canonical_cases
            .iter()
            .map(|case| format!("{case} => {{ #[tokio::test] run_{case} => behavior_{case} }}"))
            .collect::<Vec<_>>()
            .join(",\n");
        let behaviors = canonical_cases
            .iter()
            .map(|case| durable_behavior(case))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!(
            r#"
fn target(store: DemoStore) -> Target {{
    Arc::new(ConformingProjectionTarget::new(store))
}}
async fn attempt(target: Target, checkpoint: Checkpoint) -> Attempt {{
    let before = checkpoint.offset();
    let selector = selector();
    let execution = WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
        selector.projection(),
        selector.tenant(),
    ).expect("generated projection execution");
    let harness = ProjectionHarness::new(
        ProjectionProjector::with_execution(execution, selector, target)
            .expect("plan-issued execution matches selector"),
        checkpoint.clone(),
    );
    let run = harness.run(&events()).await;
    let advanced = checkpoint.offset() != before;
    if run.applied == 1 {{
        ProjectionAttemptObservation::succeeded(Applied, advanced)
    }} else {{
        ProjectionAttemptObservation::failed(Permanent)
    }}
}}
{observation}
{behaviors}
testkit::projection_target_conformance! {{ cases: {{ {cases}, }} }}
"#,
            observation = durable_observation_fn(),
        ))
    }

    fn enrollment_only(root: &Path) -> Result<Vec<Finding<Rule>>> {
        let packages = packages(root)?;
        Ok(enrollment_findings(root, &packages, &canonical_cases(root)?)?.1)
    }

    #[test]
    fn production_store_requires_canonical_enrollment() -> Result<()> {
        let root = workspace("projection-enrollment-missing-red")?;
        write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_enrollment_count")
        }));
        Ok(())
    }

    #[test]
    fn every_concrete_store_requires_its_own_enrollment() -> Result<()> {
        let root = workspace("projection-enrollment-per-impl-red")?;
        write(
            &root.join("adapters/demo/src/lib.rs"),
            "pub struct DemoStore;\nimpl ProjectionTargetStore for DemoStore {}\npub struct SecondStore;\nimpl ProjectionTargetStore for SecondStore {}\n",
        )?;
        write(
            &root.join("adapters/demo/tests/projection_target_conformance.rs"),
            &canonical_enrollment(&root)?,
        )?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_impl_enrollment")
                && finding.detail.contains("SecondStore")
        }));
        Ok(())
    }

    #[test]
    fn enrollments_cannot_share_or_evade_concrete_store_edges() -> Result<()> {
        let root = workspace("projection-enrollment-ambiguous-edge-red")?;
        write(
            &root.join("adapters/demo/src/lib.rs"),
            "pub struct DemoStore;\nimpl ProjectionTargetStore for DemoStore {}\npub struct SecondStore;\nimpl ProjectionTargetStore for SecondStore {}\n",
        )?;
        let shared = canonical_enrollment(&root)?.replacen(
            "fn target(store: DemoStore)",
            "fn target(store: (DemoStore, SecondStore))",
            1,
        );
        let unbound = canonical_enrollment(&root)?.replacen(
            "fn target(store: DemoStore)",
            "fn target(store: UnboundStore)",
            1,
        );
        write(
            &root.join("adapters/demo/tests/first_projection_target_conformance.rs"),
            &shared,
        )?;
        write(
            &root.join("adapters/demo/tests/second_projection_target_conformance.rs"),
            &unbound,
        )?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_enrollment_impl_edge")
        }));
        Ok(())
    }

    #[test]
    fn exact_set_is_read_from_testkit_catalog_owner() -> Result<()> {
        let root = workspace("projection-catalog-owner-red")?;
        let catalog = fs::read_to_string(root.join(PROJECTION_CATALOG_OWNER))?.replace(
            "Self::AtomicApply,\n        Self::SameFactDuplicate,",
            "Self::SameFactDuplicate,\n        Self::AtomicApply,",
        );
        write(&root.join(PROJECTION_CATALOG_OWNER), &catalog)?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_exact_set")
                && finding.detail.contains("same_fact_duplicate")
        }));
        Ok(())
    }

    #[test]
    fn enrollment_rejects_wrong_set_unreachable_and_noop() -> Result<()> {
        let root = workspace("projection-enrollment-shape-red")?;
        write(
            &root.join("adapters/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nautoexamples = false\n",
        )?;
        write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
        let malformed = canonical_enrollment(&root)?
            .replace("atomic_apply =>", "rollback_failed =>")
            .replace(
                "attempt(target(store.clone()), checkpoint, event()).await",
                "canned().await",
            );
        write(&root.join("adapters/demo/examples/dead.rs"), &malformed)?;
        let packages = packages(&root)?;
        let findings = enrollment_findings(&root, &packages, &canonical_cases(&root)?)?.1;
        for predicate in [
            "predicate=projection_target_exact_set",
            "predicate=projection_target_reachable_test",
            "predicate=projection_target_behavior_edge",
        ] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains(predicate)),
                "missing {predicate}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn live_behavior_rejects_dead_branch_and_canned_observation() -> Result<()> {
        let cases = [
            (
                "projection-behavior-dead-branch-red",
                r#"async fn behavior_atomic_apply() -> Result<ProjectionObservation, Error> {
    if false {
        let store = Store::new();
        let checkpoint = Checkpoint::new();
        let result = attempt(target(store.clone()), checkpoint, event()).await;
        return observation(vec![result], &store);
    }
    canned_observation()
}"#,
            ),
            (
                "projection-behavior-canned-red",
                r#"async fn behavior_atomic_apply() -> Result<ProjectionObservation, Error> {
    let store = Store::new();
    Ok(ProjectionObservation::new(vec![], 1, 1, 1))
}"#,
            ),
        ];
        for (name, replacement) in cases {
            let root = workspace(name)?;
            write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
            let source = canonical_enrollment(&root)?.replacen(
                &canonical_behavior("atomic_apply"),
                replacement,
                1,
            );
            write(
                &root.join("adapters/demo/tests/projection_target_conformance.rs"),
                &source,
            )?;
            let findings = enrollment_only(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("predicate=projection_target_behavior_live")
                }),
                "{name}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn live_observation_rejects_durable_bypasses() -> Result<()> {
        let observation = durable_observation_fn();
        let counts_funnel = r#"let (effects, receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    ).await?;"#;
        let cases = [
            (
                "projection-observation-wrong-pool-red",
                observation.replace("&owner.pool", "&store.pool"),
            ),
            (
                "projection-observation-lit-tenant-red",
                observation.replace("selector.tenant()", "\"tenant-a\""),
            ),
            (
                "projection-observation-lit-generation-red",
                observation.replace("selector.version().as_str()", "\"demo-conformance\""),
            ),
            (
                "projection-observation-mismatched-selector-red",
                observation.replace(
                    r#"let selector = demo_conformance_selector();
    let (effects, receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    ).await?;"#,
                    r#"let selector = demo_conformance_selector();
    let other = other_conformance_selector();
    let (effects, receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        other.version().as_str(),
    ).await?;"#,
                ),
            ),
            (
                "projection-observation-raw-sql-red",
                observation.replace(
                    counts_funnel,
                    r#"let (effects, receipts): (u64, u64) = sqlx::query_as(
        "select count(*) from rows"
    ).fetch_one(&owner.pool).await?;"#,
                ),
            ),
            (
                "projection-observation-no-apply-calls-red",
                observation.replace("store.apply_calls()", "1"),
            ),
            (
                "projection-observation-effects-lit-red",
                observation
                    .replace("effects, receipts)", "0, 0)")
                    .replace(
                        r#"let (effects, receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    ).await?;
    Ok(ProjectionObservation::new(attempts, store.apply_calls(), effects, receipts))"#,
                        r#"let (_effects, _receipts) = demo_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    ).await?;
    Ok(ProjectionObservation::new(attempts, store.apply_calls(), 1, 1))"#,
                    ),
            ),
            (
                "projection-rollback-tx-counts-as-durable-red",
                observation.replace(
                    r#"async fn rollback_observation(attempts: Vec<Attempt>, store: &DemoStore, owner: &Owner) -> Result<ProjectionObservation, Error> {
    let observation = observation(attempts, store, owner).await?;
    if observation.business_effects() != 0 || observation.receipts() != 0 {
        return Err(Error::Mismatch);
    }
    Ok(observation)
}"#,
                    r#"async fn rollback_observation(attempts: Vec<Attempt>, store: &DemoStore, owner: &Owner) -> Result<ProjectionObservation, Error> {
    let actual = store.transaction_counts();
    if actual != (0, 0) {
        return Err(Error::Mismatch);
    }
    let _ = owner;
    Ok(ProjectionObservation::new(attempts, 0, 0, 0))
}"#,
                ),
            ),
            (
                "projection-rollback-partial-zero-red",
                observation.replace(
                    "observation.business_effects() != 0 || observation.receipts() != 0",
                    "observation.business_effects() != 0",
                ),
            ),
        ];
        for (name, mutated) in cases {
            let root = workspace(name)?;
            write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
            let source = durable_enrollment(&root)?.replacen(observation, &mutated, 1);
            write(
                &root.join("adapters/demo/tests/projection_target_conformance.rs"),
                &source,
            )?;
            let findings = enrollment_only(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("predicate=projection_target_behavior_live")
                }),
                "{name}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn enrollment_requires_enabled_tokio_test_runners() -> Result<()> {
        let cases = [
            ("missing", "#[tokio::test]", ""),
            ("sync-test", "#[tokio::test]", "#[test]"),
            ("ignored", "#[tokio::test]", "#[ignore]\n#[tokio::test]"),
            (
                "cfg-disabled",
                "#[tokio::test]",
                "#[cfg(any())]\n#[tokio::test]",
            ),
        ];
        for (name, before, after) in cases {
            let root = workspace(&format!("projection-runner-{name}-red"))?;
            write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
            let source = canonical_enrollment(&root)?.replacen(before, after, 1);
            write(
                &root.join("adapters/demo/tests/projection_target_conformance.rs"),
                &source,
            )?;
            let findings = enrollment_only(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("predicate=projection_target_async_test_registration")
                }),
                "{name}: {findings:?}"
            );
        }

        let root = workspace("projection-runner-enclosing-cfg-red")?;
        write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
        let source = canonical_enrollment(&root)?.replace(
            "testkit::projection_target_conformance!",
            "#[cfg(any())]\ntestkit::projection_target_conformance!",
        );
        write(
            &root.join("adapters/demo/tests/projection_target_conformance.rs"),
            &source,
        )?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_async_test_registration")
        }));
        Ok(())
    }

    #[test]
    fn cargo_globs_and_custom_production_targets_remain_scanned() -> Result<()> {
        for (kind, path) in [
            ("bin", "custom/driver.rs"),
            ("example", "custom/example.rs"),
            ("bench", "custom/bench.rs"),
        ] {
            let root = workspace(&format!("projection-custom-{kind}-red"))?;
            write(
                &root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"adapters/*\", \"crates/*\"]\n",
            )?;
            let manifest = format!(
                "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n\n[[{kind}]]\nname = \"projection-owner\"\npath = \"{path}\"\n"
            );
            write(&root.join("adapters/demo/Cargo.toml"), &manifest)?;
            write(&root.join("adapters/demo/src/lib.rs"), "pub fn live() {}")?;
            write(&root.join("adapters/demo").join(path), store_source())?;
            let findings = enrollment_only(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("predicate=projection_target_enrollment_count")
                }),
                "{kind}: {findings:?}"
            );
        }

        let root = workspace("projection-autoexample-disabled-red")?;
        write(
            &root.join("adapters/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nautoexamples = false\n",
        )?;
        write(&root.join("adapters/demo/src/lib.rs"), "pub fn live() {}")?;
        write(
            &root.join("adapters/demo/examples/orphan.rs"),
            store_source(),
        )?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_tracked_source")
        }));
        Ok(())
    }

    #[test]
    fn opaque_external_item_macro_attribute_and_derive_are_rejected() -> Result<()> {
        let cases = [
            ("item-macro", "external_codegen::impl_projection_store!();"),
            (
                "proc-attribute",
                "#[external_codegen::impl_projection_store]\npub struct DemoStore;",
            ),
            (
                "custom-derive",
                "#[derive(external_codegen::ProjectionStore)]\npub struct DemoStore;",
            ),
        ];
        for (name, opaque_source) in cases {
            let root = workspace(&format!("projection-external-{name}-red"))?;
            write(
                &root.join("adapters/demo/Cargo.toml"),
                "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n[dependencies]\neventexec = { path = \"../../crates/eventexec\" }\nexternal_codegen = { path = \"../../crates/external-codegen\" }\n",
            )?;
            let source = format!(
                "{opaque_source}\npub struct DemoStore;\nimpl ProjectionTargetStore for DemoStore {{}}\n"
            );
            write(&root.join("adapters/demo/src/lib.rs"), &source)?;
            let findings = enrollment_only(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("predicate=projection_target_opaque_codegen")
                }),
                "{name}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn opaque_codegen_in_unrelated_eventexec_consumer_is_not_scanned() -> Result<()> {
        let root = workspace("projection-opaque-unrelated-green")?;
        write(
            &root.join("adapters/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n[dependencies]\neventexec = { path = \"../../crates/eventexec\" }\n",
        )?;
        write(
            &root.join("adapters/demo/src/lib.rs"),
            "external_codegen::unrelated!();\n#[derive(external_codegen::Unrelated)]\npub struct Value;\n",
        )?;
        let findings = enrollment_only(&root)?;
        assert!(!findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_opaque_codegen")
        }));
        Ok(())
    }

    #[test]
    fn untracked_store_source_is_rejected() -> Result<()> {
        let root = workspace("projection-enrollment-untracked-red")?;
        write(&root.join("adapters/demo/src/lib.rs"), "pub fn live() {}")?;
        write(&root.join("adapters/demo/src/orphan.rs"), store_source())?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_tracked_source")
        }));
        Ok(())
    }

    #[test]
    fn macro_hidden_store_impl_is_rejected() -> Result<()> {
        let root = workspace("projection-enrollment-macro-red")?;
        write(
            &root.join("adapters/demo/src/lib.rs"),
            "use eventexec::ProjectionTargetStore as HiddenStore; macro_rules! hidden { () => { impl ProjectionTargetStore for Hidden {} } }",
        )?;
        let findings = enrollment_only(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_store_ast_bypass")
        }));
        Ok(())
    }

    #[test]
    fn canonical_store_enrollment_is_accepted() -> Result<()> {
        let root = workspace("projection-enrollment-green")?;
        write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
        write(
            &root.join("adapters/demo/tests/projection_target_conformance.rs"),
            &canonical_enrollment(&root)?,
        )?;
        assert_eq!(enrollment_only(&root)?, Vec::<Finding<Rule>>::new());
        Ok(())
    }

    #[test]
    fn durable_owner_pool_observation_enrollment_is_accepted() -> Result<()> {
        let root = workspace("projection-durable-observation-green")?;
        write(&root.join("adapters/demo/src/lib.rs"), store_source())?;
        write(
            &root.join("adapters/demo/tests/projection_target_conformance.rs"),
            &durable_enrollment(&root)?,
        )?;
        assert_eq!(enrollment_only(&root)?, Vec::<Finding<Rule>>::new());
        Ok(())
    }

    #[test]
    fn runtime_funnel_rejects_bypasses() -> Result<()> {
        let root = workspace("projection-funnel-red")?;
        write(
            &root.join("adapters/demo/src/lib.rs"),
            "pub struct Bypass; impl ProjectionTarget for Bypass {} fn forge() { let _ = ValidatedProjectionApply { value: 2 }; } fn replay_target() {} macro_rules! hidden { () => { impl ProjectionTarget for Hidden {} } }",
        )?;
        let packages = packages(&root)?;
        let findings = runtime_funnel_findings(&root, &packages)?;
        for predicate in [
            "predicate=projection_target_sealed_impl",
            "predicate=projection_target_private_input",
            "predicate=projection_target_no_legacy",
            "predicate=projection_target_macro_bypass",
        ] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains(predicate)),
                "missing {predicate}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn empty_store_inventory_requires_disabled_projection_activations() -> Result<()> {
        let root = crate::assembly_governance::AssemblyFixtureRepository::create()?;
        populate_workspace(&root)?;
        write(&root.join("adapters/demo/src/lib.rs"), "pub fn live() {}")?;
        let workspace_root = crate::workspace_root()?;
        let manifest =
            fs::read_to_string(workspace_root.join("assemblies/settingsonly/assembly.toml"))?
                .replace("name = \"settingsonly\"", "name = \"demo\"")
                .replace("profile = \"production\"", "profile = \"demo\"")
                .replace("activation = \"disabled\"", "activation = \"active\"");
        write(&root.join("assemblies/demo/assembly.toml"), &manifest)?;
        write(
            &root.join("assemblies/demo/Cargo.toml"),
            &fs::read_to_string(workspace_root.join("assemblies/settingsonly/Cargo.toml"))?
                .replace("settingsonly", "demo"),
        )?;
        crate::assembly_governance::AssemblyFixtureBuilder::complete_production_universe(&root)?;
        let findings = disabled_activation_findings(&root)?;
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("predicate=projection_target_empty_inventory_disabled")
        }));
        Ok(())
    }

    #[test]
    fn workspace_projection_target_guard_is_green() -> Result<()> {
        let root = crate::workspace_root()?;
        assert_eq!(findings(&root)?, Vec::<Finding<Rule>>::new());
        Ok(())
    }
}
