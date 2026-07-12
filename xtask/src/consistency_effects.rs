//! Static LocalOnly route/state/port effect closure gate.
//!
//! INVARIANT: LOCAL-ONLY-EFFECTS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "forged_observation_provenance_is_rejected", anti_vacuity = "governed_observation_provenance_is_accepted" }.

use crate::contract::DiscoveredContract;
use crate::contract::manifest::{
    ConsistencyLevel, ContractKind, ContractOwner, EffectKind, HttpMethod, Lifecycle,
};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, GenericArgument, ImplItem, Item, ItemImpl, ItemStruct, ItemType, PathArguments, Type,
    TypeParamBound,
};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    MissingRouteBinding,
    UnclassifiedState,
    ForbiddenStateEffect,
    CrossTenantPrivilege,
    OpaqueSourceScope,
    ForgedObservationEvidence,
}

pub(crate) struct LocalOnlyEffects;

impl GovernanceCheck for LocalOnlyEffects {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "consistency local-only-effects"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        check_root(&crate::workspace_root()?)
    }
}

#[derive(Debug, Clone)]
struct Contract {
    id: String,
    owner: String,
    key: String,
    method: String,
    path: String,
    subject: String,
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding>)> {
    let discovered = discover_without_absolute_paths(root)?;
    let (contracts, mut findings) = contracts_and_profile_findings(root, &discovered)?;
    // Contract-only fixtures are intentionally supported by the cross-field unit tests. A real
    // workspace always has Cargo.toml and therefore must close generated/source evidence.
    if root.join("Cargo.toml").is_file() {
        findings.extend(source_findings(root, &contracts)?);
        findings.extend(observation_provenance_findings(root)?);
    }
    findings
        .sort_by(|a, b| (&a.rule, &a.subject, &a.detail).cmp(&(&b.rule, &b.subject, &b.detail)));
    findings.dedup();
    Ok((
        format!(
            "{} active LocalOnly HTTP contract(s) checked",
            contracts.len()
        ),
        findings,
    ))
}

fn discover_without_absolute_paths(root: &Path) -> Result<Vec<DiscoveredContract>> {
    crate::contract::discover(&root.join("contracts")).map_err(|error| {
        let root_text = root.to_string_lossy();
        anyhow!(format!("{error:#}").replace(root_text.as_ref(), "."))
    })
}

fn contracts_and_profile_findings(
    root: &Path,
    discovered: &[DiscoveredContract],
) -> Result<(Vec<Contract>, Vec<Finding>)> {
    let mut contracts = Vec::new();
    let mut findings = Vec::new();
    for item in discovered {
        let manifest = &item.manifest;
        if manifest.lifecycle != Lifecycle::Active
            || manifest.kind != ContractKind::Http
            || manifest.consistency_level != ConsistencyLevel::LocalOnly
        {
            continue;
        }
        let subject = relative_manifest_path(root, item)?;
        let path = required_path(manifest.path.as_deref(), &subject, &manifest.id)?.to_string();
        let method = required_method(manifest.method, &subject, &manifest.id)?
            .as_wire()
            .to_string();
        let owner = match &manifest.owner {
            ContractOwner::Domain(owner) if owner == &manifest.domain => owner.clone(),
            _ => bail!(
                "{subject}: LocalOnly contract `{}` must have its domain as owner",
                manifest.id
            ),
        };
        let profile = manifest.effect_profile.as_ref().ok_or_else(|| {
            anyhow!(
                "{subject}: active LocalOnly HTTP contract `{}` missing `effectProfile`",
                manifest.id
            )
        })?;
        for effect in profile
            .effects
            .iter()
            .copied()
            .filter_map(forbidden_effect_wire)
        {
            findings.push(contract_finding(
                Rule::ForbiddenStateEffect,
                &manifest.id,
                &method,
                &path,
                &subject,
                effect,
                "unknown",
                "manifest effectProfile",
            ));
        }
        contracts.push(Contract {
            id: manifest.id.clone(),
            owner,
            key: generated_key(&manifest.domain, &manifest.version, item.slug.as_deref()),
            method,
            path,
            subject,
        });
    }
    contracts.sort_by(|a, b| (&a.id, &a.subject).cmp(&(&b.id, &b.subject)));
    Ok((contracts, findings))
}

fn source_findings(root: &Path, contracts: &[Contract]) -> Result<Vec<Finding>> {
    let generated = generated_localonly_routes(root)?;
    let mut by_owner: BTreeMap<&str, Vec<&Contract>> = BTreeMap::new();
    for contract in contracts {
        by_owner.entry(&contract.owner).or_default().push(contract);
    }
    let mut findings = Vec::new();
    for (owner, owned) in by_owner {
        let evidence = crate::localtx_coverage::canonical_owner_evidence(root, owner)
            .map_err(|error| sanitized(root, error))?;
        let source = OwnerSource::load(root, owner, &evidence.reachable_production_sources)?;
        for contract in owned {
            if !generated.contains(&contract.key) || !evidence.mounts.contains_key(&contract.key) {
                findings.push(contract_finding(
                    Rule::MissingRouteBinding,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &contract.subject,
                    "unknown",
                    "unknown",
                    "generated typed ROUTE or canonical Domain::init mount is missing",
                ));
                continue;
            }
            let Some(mounts) = evidence.mounts.get(&contract.key) else {
                findings.push(contract_finding(
                    Rule::MissingRouteBinding,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &contract.subject,
                    "unknown",
                    "unknown",
                    "mounted endpoint expression cannot be resolved",
                ));
                continue;
            };
            if mounts.len() != 1 {
                findings.push(contract_finding(
                    Rule::OpaqueSourceScope,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &contract.subject,
                    "unknown",
                    "unknown",
                    "route has conflicting endpoint/state evidence (dead or unmounted spoof included)",
                ));
                continue;
            }
            let Some(mount) = mounts.iter().next() else {
                continue;
            };
            use crate::localtx_coverage::CanonicalMountedState;
            match &mount.state {
                CanonicalMountedState::Stateless => {}
                CanonicalMountedState::Ordinary => findings.push(contract_finding(
                    Rule::UnclassifiedState,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &contract.subject,
                    "unknown",
                    "unknown",
                    "LocalOnly endpoint uses ordinary with_state",
                )),
                CanonicalMountedState::Opaque => findings.push(contract_finding(
                    Rule::OpaqueSourceScope,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &mount.source,
                    "unknown",
                    "unknown",
                    "classified state expression is opaque",
                )),
                CanonicalMountedState::Classified(expression) => {
                    let state = source.state_name(&mount.source, expression);
                    let Some(state) = state else {
                        findings.push(contract_finding(
                            Rule::OpaqueSourceScope,
                            &contract.id,
                            &contract.method,
                            &contract.path,
                            &mount.source,
                            "unknown",
                            "unknown",
                            "classified state expression is not a canonical named struct",
                        ));
                        continue;
                    };
                    match source.classify_state(&state) {
                        Ok(classification) => {
                            if classification.privilege == "CrossTenantPrivilege" {
                                findings.push(classified_finding(
                                    Rule::CrossTenantPrivilege,
                                    contract,
                                    &state,
                                    &classification,
                                ));
                            }
                            if !matches!(
                                classification.effect.as_str(),
                                "ReadEffect" | "AuthEffect"
                            ) {
                                findings.push(classified_finding(
                                    Rule::ForbiddenStateEffect,
                                    contract,
                                    &state,
                                    &classification,
                                ));
                            }
                        }
                        Err(error) => {
                            let error = format!("state `{state}`: {error}");
                            let subject = diagnostic_source(&error)
                                .unwrap_or_else(|| contract.subject.clone());
                            findings.push(contract_finding(
                                if source.states.contains_key(&state) {
                                    Rule::OpaqueSourceScope
                                } else {
                                    Rule::UnclassifiedState
                                },
                                &contract.id,
                                &contract.method,
                                &contract.path,
                                &subject,
                                "unknown",
                                "unknown",
                                &error,
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(findings)
}

/// Closes the runtime-observation provenance seam left deliberately open by `testkit`'s zero
/// workspace-dependency boundary. The native types make dimensions and proof values
/// non-interchangeable; this source gate binds those values back to the canonical owner-side
/// provider/route evidence. Only direct, mechanically auditable shapes are accepted. Wrappers and
/// aliases that the scanner cannot prove are rejected instead of guessed through.
fn observation_provenance_findings(root: &Path) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    for member in workspace_member_paths(root)? {
        if member == Path::new("crates/testkit") {
            continue;
        }
        for source_root in [
            root.join(&member).join("src"),
            root.join(&member).join("tests"),
        ] {
            if source_root.is_dir() {
                files.extend(rust_files(&source_root)?);
            }
        }
    }
    files.sort();

    let mut parsed = Vec::new();
    for file in files {
        let subject = relative(root, &file)?;
        let syntax = syn::parse_file(
            &std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?,
        )
        .with_context(|| format!("parse `{subject}`"))?;
        let mut recorded_provider_fields = BTreeMap::new();
        collect_recorded_provider_fields(&syntax.items, &mut recorded_provider_fields);
        parsed.push((subject, syntax, recorded_provider_fields));
    }

    let mut findings = Vec::new();
    for (subject, syntax, recorded_provider_fields) in &parsed {
        provenance_findings_in_items(
            &syntax.items,
            subject,
            recorded_provider_fields,
            &mut findings,
        );
    }
    Ok(findings)
}

fn workspace_member_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest = root.join("Cargo.toml");
    let value: toml::Value = toml::from_str(
        &std::fs::read_to_string(&manifest).with_context(|| "read workspace Cargo.toml")?,
    )
    .context("parse workspace Cargo.toml")?;
    let members = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("workspace.members must be an explicit array"))?;
    let mut paths = Vec::new();
    for member in members {
        let member = member
            .as_str()
            .ok_or_else(|| anyhow!("workspace member must be a string"))?;
        if member.contains(['*', '?', '[', ']']) {
            bail!("workspace member globs are opaque to LocalOnly provenance: `{member}`");
        }
        let path = PathBuf::from(member);
        if path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            bail!("workspace member escapes the repository: `{member}`");
        }
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect_recorded_provider_fields(items: &[Item], out: &mut BTreeMap<String, BTreeSet<String>>) {
    for item in items {
        match item {
            Item::Impl(item) => {
                if let Some(owner) = terminal_type_ident(&item.self_ty) {
                    let fields = directly_recorded_fields(&item.items);
                    if !fields.is_empty() {
                        out.entry(owner).or_default().extend(fields);
                    }
                }
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_recorded_provider_fields(nested, out);
                }
            }
            _ => {}
        }
    }
}

fn directly_recorded_fields(items: &[ImplItem]) -> BTreeSet<String> {
    struct Calls {
        fields: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "record"
                && let Expr::Field(field) = peel_expr(&node.receiver)
                && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
                && let syn::Member::Named(member) = &field.member
            {
                self.fields.insert(member.to_string());
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut calls = Calls {
        fields: BTreeSet::new(),
    };
    for item in items {
        calls.visit_impl_item(item);
    }
    calls.fields
}

fn provenance_findings_in_items(
    items: &[Item],
    subject: &str,
    recorded_provider_fields: &BTreeMap<String, BTreeSet<String>>,
    findings: &mut Vec<Finding>,
) {
    for item in items {
        match item {
            Item::Use(item) if use_tree_contains_local_only_api(&item.tree) => {
                push_provenance_finding(
                    findings,
                    subject,
                    item.span().start().line,
                    "LocalOnly evidence APIs may not be imported or renamed; use exact absolute paths",
                );
            }
            Item::Type(item) if type_contains_local_only_api(&item.ty) => {
                push_provenance_finding(
                    findings,
                    subject,
                    item.span().start().line,
                    "LocalOnly evidence API type aliases are forbidden",
                );
            }
            Item::Fn(function) => provenance_findings_in_function(
                function,
                subject,
                recorded_provider_fields,
                findings,
            ),
            Item::Impl(item) => {
                if item.trait_.as_ref().is_some_and(|(_, path, _)| {
                    path.segments
                        .last()
                        .is_some_and(|segment| segment.ident == "StaticExclusionOwner")
                }) {
                    push_provenance_finding(
                        findings,
                        subject,
                        item.span().start().line,
                        "legacy StaticExclusionOwner impl is forgeable; use an httpserve governed proof",
                    );
                }
                for child in &item.items {
                    if let ImplItem::Fn(function) = child {
                        provenance_findings_in_impl_function(
                            function,
                            subject,
                            recorded_provider_fields,
                            findings,
                        );
                    }
                }
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    provenance_findings_in_items(
                        nested,
                        subject,
                        recorded_provider_fields,
                        findings,
                    );
                }
            }
            _ => {}
        }
    }
}

fn use_tree_contains_local_only_api(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            is_local_only_api_ident(&path.ident) || use_tree_contains_local_only_api(&path.tree)
        }
        syn::UseTree::Name(name) => is_local_only_api_ident(&name.ident),
        syn::UseTree::Rename(rename) => is_local_only_api_ident(&rename.ident),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_contains_local_only_api),
        syn::UseTree::Glob(_) => false,
    }
}

fn type_contains_local_only_api(ty: &Type) -> bool {
    struct ApiType(bool);
    impl<'ast> Visit<'ast> for ApiType {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            if node
                .path
                .segments
                .iter()
                .any(|segment| is_local_only_api_ident(&segment.ident))
            {
                self.0 = true;
            }
            visit::visit_type_path(self, node);
        }
    }
    let mut found = ApiType(false);
    found.visit_type(ty);
    found.0
}

fn is_local_only_api_ident(ident: &syn::Ident) -> bool {
    matches!(
        ident.to_string().as_str(),
        "LocalOnlyObservers" | "StaticExclusion" | "ProviderCounter" | "ProviderCounterHandle"
    )
}

fn provenance_findings_in_function(
    function: &syn::ItemFn,
    subject: &str,
    recorded_provider_fields: &BTreeMap<String, BTreeSet<String>>,
    findings: &mut Vec<Finding>,
) {
    provenance_findings_in_block(&function.block, subject, recorded_provider_fields, findings);
}

fn provenance_findings_in_impl_function(
    function: &syn::ImplItemFn,
    subject: &str,
    recorded_provider_fields: &BTreeMap<String, BTreeSet<String>>,
    findings: &mut Vec<Finding>,
) {
    provenance_findings_in_block(&function.block, subject, recorded_provider_fields, findings);
}

fn provenance_findings_in_block(
    block: &syn::Block,
    subject: &str,
    recorded_provider_fields: &BTreeMap<String, BTreeSet<String>>,
    findings: &mut Vec<Finding>,
) {
    let bindings = direct_initializer_bindings(block);
    let provider_routers = canonical_provider_router_bindings(&bindings);
    let mut scan = ProvenanceCallScan::default();
    scan.visit_block(block);

    for line in scan.legacy_evidence_lines {
        findings.push(finding(
            Rule::ForgedObservationEvidence,
            format!("{subject}:{line}"),
            "legacy RuntimeProbe/StaticExclusionOwner evidence is forgeable; use governed proof or provider-owned counter handle",
        ));
    }
    for (line, _) in scan
        .api_expr_locations
        .difference(&scan.allowed_api_locations)
    {
        push_provenance_finding(
            findings,
            subject,
            *line,
            "LocalOnly evidence API must be invoked through its exact absolute canonical path",
        );
    }

    for call in scan.from_governed_calls {
        let Some(argument) = call.args.first() else {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed requires one direct governed proof binding",
            );
            continue;
        };
        let Some(proof) = referenced_ident(argument) else {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed argument must be `&proof`, not an inline value or wrapper",
            );
            continue;
        };
        if bindings
            .get(&proof)
            .is_none_or(|initializer| !is_governed_proof_constructor(initializer))
        {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed proof is not bound directly from prove_local_only_state/prove_stateless_local_only_route",
            );
        }
    }

    for observer in scan.observer_calls {
        for argument in &observer.args {
            let resolved = resolve_direct_binding(argument, &bindings);
            let Some(handle) = find_method_call(resolved, "handle") else {
                if is_from_governed_call(resolved) {
                    continue;
                }
                push_provenance_finding(
                    findings,
                    subject,
                    argument.span().start().line,
                    "LocalOnly observer evidence is neither a direct governed exclusion nor a provider-owned counter handle",
                );
                continue;
            };
            let Some(provider) = root_receiver_ident(&handle.receiver) else {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider counter handle receiver is opaque",
                );
                continue;
            };
            if provider_routers
                .get(&provider)
                .is_none_or(|routers| routers.is_disjoint(&scan.oneshot_router_receivers))
            {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider handle is not linked through finalized_scoped_router(receiver.test_repo()) to the router.oneshot operation",
                );
                continue;
            }
            let provider_type = bindings.get(&provider).and_then(unique_constructor_owner);
            let counter_field = direct_receiver_field(&handle.receiver, &provider);
            if provider_type.as_ref().is_none_or(|owner| {
                counter_field.as_ref().is_none_or(|field| {
                    recorded_provider_fields
                        .get(owner)
                        .is_none_or(|fields| !fields.contains(field))
                })
            }) {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider counter field has no matching `self.<field>.record()` mutation path",
                );
            }
        }
    }
}

fn canonical_provider_router_bindings(
    bindings: &BTreeMap<String, Expr>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (router, initializer) in bindings {
        let Expr::Call(call) = peel_expr(initializer) else {
            continue;
        };
        let Expr::Path(function) = peel_expr(&call.func) else {
            continue;
        };
        if function.path.leading_colon.is_some()
            || function.path.segments.len() != 1
            || function.path.segments[0].ident != "finalized_scoped_router"
        {
            continue;
        }
        for argument in &call.args {
            let Expr::MethodCall(method) = peel_expr(argument) else {
                continue;
            };
            if method.method == "test_repo"
                && method.args.is_empty()
                && let Some(provider) = root_receiver_ident(&method.receiver)
            {
                out.entry(provider).or_default().insert(router.clone());
            }
        }
    }
    out
}

fn direct_receiver_field(expression: &Expr, provider: &str) -> Option<String> {
    let Expr::Field(field) = peel_expr(expression) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    let Expr::Path(base) = peel_expr(&field.base) else {
        return None;
    };
    (base.path.get_ident().is_some_and(|ident| ident == provider)).then(|| member.to_string())
}

fn push_provenance_finding(
    findings: &mut Vec<Finding>,
    subject: &str,
    line: usize,
    detail: &'static str,
) {
    findings.push(finding(
        Rule::ForgedObservationEvidence,
        format!("{subject}:{line}"),
        detail,
    ));
}

#[derive(Default)]
struct ProvenanceCallScan<'ast> {
    from_governed_calls: Vec<&'ast syn::ExprCall>,
    observer_calls: Vec<&'ast syn::ExprCall>,
    oneshot_router_receivers: BTreeSet<String>,
    legacy_evidence_lines: BTreeSet<usize>,
    api_expr_locations: BTreeSet<(usize, usize)>,
    allowed_api_locations: BTreeSet<(usize, usize)>,
}

impl<'ast> Visit<'ast> for ProvenanceCallScan<'ast> {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "StaticExclusionOwner" | "RuntimeProbe"
            )
        }) {
            self.legacy_evidence_lines.insert(node.span().start().line);
        }
        visit::visit_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "LocalOnlyObservers"
                    | "StaticExclusion"
                    | "ProviderCounter"
                    | "prove_local_only_state"
                    | "prove_stateless_local_only_route"
            )
        }) {
            let start = node.span().start();
            self.api_expr_locations.insert((start.line, start.column));
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let start = node.func.span().start();
        let location = (start.line, start.column);
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "StaticExclusion", "from_governed"],
        ) {
            self.from_governed_calls.push(node);
            self.allowed_api_locations.insert(location);
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "LocalOnlyObservers", "new"],
        ) {
            self.observer_calls.push(node);
            self.allowed_api_locations.insert(location);
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "ProviderCounter", "write"],
        ) || absolute_call_path_is(&node.func, &["httpserve", "prove_local_only_state"])
            || absolute_call_path_is(
                &node.func,
                &["httpserve", "prove_stateless_local_only_route"],
            )
        {
            self.allowed_api_locations.insert(location);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "oneshot"
            && let Some(receiver) = root_receiver_ident(&node.receiver)
        {
            self.oneshot_router_receivers.insert(receiver);
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn direct_initializer_bindings(block: &syn::Block) -> BTreeMap<String, Expr> {
    struct Bindings(BTreeMap<String, Expr>);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let syn::Pat::Ident(pattern) = &node.pat
                && pattern.subpat.is_none()
                && let Some(initializer) = &node.init
            {
                self.0
                    .insert(pattern.ident.to_string(), (*initializer.expr).clone());
            }
            visit::visit_local(self, node);
        }
    }
    let mut bindings = Bindings(BTreeMap::new());
    bindings.visit_block(block);
    bindings.0
}

fn resolve_direct_binding<'a>(
    expression: &'a Expr,
    bindings: &'a BTreeMap<String, Expr>,
) -> &'a Expr {
    let Expr::Path(path) = peel_expr(expression) else {
        return expression;
    };
    let Some(ident) = path.path.get_ident() else {
        return expression;
    };
    bindings.get(&ident.to_string()).unwrap_or(expression)
}

fn referenced_ident(expression: &Expr) -> Option<String> {
    let expression = match expression {
        Expr::Paren(value) => &*value.expr,
        Expr::Group(value) => &*value.expr,
        other => other,
    };
    let Expr::Reference(reference) = expression else {
        return None;
    };
    let Expr::Path(path) = peel_expr(&reference.expr) else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

fn is_governed_proof_constructor(expression: &Expr) -> bool {
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    absolute_call_path_is(&call.func, &["httpserve", "prove_local_only_state"])
        || absolute_call_path_is(
            &call.func,
            &["httpserve", "prove_stateless_local_only_route"],
        )
}

fn is_from_governed_call(expression: &Expr) -> bool {
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    absolute_call_path_is(
        &call.func,
        &["testkit", "local_only", "StaticExclusion", "from_governed"],
    )
}

fn find_method_call<'ast>(
    expression: &'ast Expr,
    method: &str,
) -> Option<&'ast syn::ExprMethodCall> {
    struct Finder<'name, 'ast> {
        method: &'name str,
        found: Option<&'ast syn::ExprMethodCall>,
    }
    impl<'ast> Visit<'ast> for Finder<'_, 'ast> {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.found.is_none() && node.method == self.method {
                self.found = Some(node);
                return;
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut finder = Finder {
        method,
        found: None,
    };
    finder.visit_expr(expression);
    finder.found
}

fn root_receiver_ident(expression: &Expr) -> Option<String> {
    match peel_expr(expression) {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => root_receiver_ident(&field.base),
        Expr::MethodCall(call) => root_receiver_ident(&call.receiver),
        Expr::Reference(reference) => root_receiver_ident(&reference.expr),
        _ => None,
    }
}

fn unique_constructor_owner(expression: &Expr) -> Option<String> {
    struct Constructors(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Constructors {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Expr::Path(path) = peel_expr(&node.func)
                && let Some(owner) = path.path.segments.iter().rev().nth(1)
            {
                self.0.insert(owner.ident.to_string());
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut constructors = Constructors(BTreeSet::new());
    constructors.visit_expr(expression);
    (constructors.0.len() == 1)
        .then(|| constructors.0.into_iter().next())
        .flatten()
}

fn absolute_call_path_is(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = peel_expr(expression) else {
        return false;
    };
    path.path.leading_colon.is_some()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.ident == *expected)
}

#[derive(Debug, Clone)]
struct StateImpl {
    effect: String,
    privilege: String,
    subject: String,
}

#[derive(Clone)]
struct StructField {
    ty: Type,
    subject: String,
}

#[derive(Clone)]
struct StructInfo {
    fields: Vec<StructField>,
    named_fields: BTreeMap<String, String>,
    subject: String,
}

#[derive(Debug, Clone)]
struct PortClass {
    effect: String,
    privilege: String,
    subject: String,
    port: String,
    privilege_subject: String,
    privilege_port: String,
}

#[derive(Clone)]
struct TypeAlias {
    ty: Type,
    params: Vec<String>,
    subject: String,
}

struct OwnerSource {
    states: BTreeMap<String, StateImpl>,
    structs: BTreeMap<String, StructInfo>,
    ports: BTreeMap<String, PortClass>,
    type_aliases: BTreeMap<String, TypeAlias>,
    bindings: BTreeMap<String, BTreeMap<String, String>>,
    trusted_port_macros: BTreeSet<String>,
}

impl OwnerSource {
    fn load(root: &Path, owner: &str, reachable: &BTreeSet<String>) -> Result<Self> {
        let mut this = Self {
            states: BTreeMap::new(),
            structs: BTreeMap::new(),
            ports: BTreeMap::new(),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        for subject in reachable {
            let file = root.join(subject);
            let text =
                std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?;
            let syntax = syn::parse_file(&text).with_context(|| format!("parse `{subject}`"))?;
            collect_trusted_port_macro_definitions(
                &syntax.items,
                subject,
                owner,
                &mut this.trusted_port_macros,
            )?;
            collect_items(&syntax.items, subject, owner, &mut this)?;
            let bindings = binding_types(&syntax, &this.structs);
            this.bindings.insert(subject.clone(), bindings);
        }
        collect_diport_capabilities(root, &mut this.ports)?;
        if !this.ports.is_empty() && this.trusted_port_macros.is_empty() {
            bail!("owner port classifications lack a canonical owner-sealed macro definition");
        }
        Ok(this)
    }

    fn state_name(&self, source: &str, expression: &str) -> Option<String> {
        let expression = syn::parse_str::<Expr>(expression).ok()?;
        let bindings = self.bindings.get(source)?;
        state_expr_name(&expression, bindings)
    }

    fn classify_state(&self, state: &str) -> Result<PortClass> {
        let declared = self.states.get(state).ok_or_else(|| {
            let subject = self
                .structs
                .get(state)
                .map_or("unknown state", |info| info.subject.as_str());
            anyhow!("{subject}: missing canonical ClassifiedRouteState impl")
        })?;
        let mut visiting = BTreeSet::new();
        let inferred = self
            .infer_struct(state, &mut visiting)?
            .ok_or_else(|| anyhow!("state graph exposes no owner-sealed classified port"))?;
        if declared.effect != inferred.effect || declared.privilege != inferred.privilege {
            bail!(
                "{}: strongest field `{}` {}/{} disagrees with state declaration {}/{} at {}",
                inferred.subject,
                inferred.port,
                inferred.effect,
                inferred.privilege,
                declared.effect,
                declared.privilege,
                declared.subject
            );
        }
        Ok(PortClass {
            effect: declared.effect.clone(),
            privilege: declared.privilege.clone(),
            subject: inferred.subject,
            port: inferred.port,
            privilege_subject: inferred.privilege_subject,
            privilege_port: inferred.privilege_port,
        })
    }

    fn infer_struct(
        &self,
        name: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<PortClass>> {
        if !visiting.insert(name.to_string()) {
            bail!("recursive state/service struct graph");
        }
        let info = self
            .structs
            .get(name)
            .ok_or_else(|| anyhow!("state/service struct `{name}` is not uniquely defined"))?;
        let mut classes = Vec::new();
        for field in &info.fields {
            let mut alias_visiting = BTreeSet::new();
            self.infer_type(
                &field.ty,
                &BTreeMap::new(),
                visiting,
                &mut alias_visiting,
                &field.subject,
                &mut classes,
            )?;
        }
        visiting.remove(name);
        let Some(effect) = classes
            .iter()
            .max_by_key(|class| effect_rank(&class.effect))
        else {
            // Non-port local values/caches are outside this static port proof and are covered by
            // the runtime conformance boundary (#1694). They cannot hide a `Dyn*` port: an
            // unclassified dyn capability above is fail-closed.
            if self.states.contains_key(name) {
                bail!(
                    "{}: state graph exposes no owner-sealed classified port",
                    info.subject
                );
            }
            return Ok(None);
        };
        let privilege = classes
            .iter()
            .find(|class| class.privilege == "CrossTenantPrivilege")
            .unwrap_or(effect);
        Ok(Some(PortClass {
            effect: effect.effect.clone(),
            privilege: privilege.privilege.clone(),
            subject: effect.subject.clone(),
            port: effect.port.clone(),
            privilege_subject: privilege.privilege_subject.clone(),
            privilege_port: privilege.privilege_port.clone(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn infer_type(
        &self,
        ty: &Type,
        substitutions: &BTreeMap<String, Type>,
        struct_visiting: &mut BTreeSet<String>,
        alias_visiting: &mut BTreeSet<String>,
        field_subject: &str,
        out: &mut Vec<PortClass>,
    ) -> Result<()> {
        match ty {
            Type::Path(path) if path.qself.is_none() => {
                let Some(segment) = path.path.segments.last() else {
                    return Ok(());
                };
                let name = segment.ident.to_string();
                if let Some(replacement) = substitutions.get(&name) {
                    return self.infer_type(
                        replacement,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    );
                }
                if let Some(alias) = self.type_aliases.get(&name) {
                    if !alias_visiting.insert(name.clone()) {
                        bail!("{}: recursive type alias `{name}`", alias.subject);
                    }
                    let args = type_arguments(&segment.arguments);
                    if args.len() != alias.params.len() {
                        bail!(
                            "{}: type alias `{name}` expects {} type argument(s), found {}",
                            alias.subject,
                            alias.params.len(),
                            args.len()
                        );
                    }
                    let mut nested = substitutions.clone();
                    nested.extend(alias.params.iter().cloned().zip(args));
                    self.infer_type(
                        &alias.ty,
                        &nested,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                    alias_visiting.remove(&name);
                    return Ok(());
                }
                if let Some(class) = self.ports.get(&name) {
                    out.push(class.at_field(field_subject));
                    return Ok(());
                }
                if self.structs.contains_key(&name) {
                    if let Some(class) = self.infer_struct(&name, struct_visiting)? {
                        out.push(class);
                    }
                    return Ok(());
                }
                if name.starts_with("Dyn") {
                    bail!("{field_subject}: capability `{name}` is not owner-sealed or classified");
                }
                for argument in type_arguments(&segment.arguments) {
                    self.infer_type(
                        &argument,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                }
            }
            Type::TraitObject(object) => {
                let mut principal = Vec::new();
                for bound in &object.bounds {
                    let TypeParamBound::Trait(bound) = bound else {
                        continue;
                    };
                    let Some(segment) = bound.path.segments.last() else {
                        continue;
                    };
                    let name = segment.ident.to_string();
                    if matches!(name.as_str(), "Send" | "Sync" | "Unpin") {
                        continue;
                    }
                    principal.push(name);
                }
                if principal.len() != 1 {
                    bail!("{field_subject}: trait object has no unique classified capability");
                }
                let name = &principal[0];
                let class = self.class_for_trait(name).ok_or_else(|| {
                    anyhow!(
                        "{field_subject}: trait object capability `{name}` is not owner-sealed or classified"
                    )
                })?;
                out.push(class.at_field(field_subject));
            }
            Type::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.infer_type(
                        element,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                }
            }
            Type::Array(array) => self.infer_type(
                &array.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Slice(slice) => self.infer_type(
                &slice.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Reference(reference) => self.infer_type(
                &reference.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Ptr(pointer) => self.infer_type(
                &pointer.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Paren(paren) => self.infer_type(
                &paren.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Group(group) => self.infer_type(
                &group.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::ImplTrait(_) => {
                bail!("{field_subject}: opaque impl Trait capability is forbidden")
            }
            _ => {}
        }
        Ok(())
    }

    fn class_for_trait(&self, name: &str) -> Option<&PortClass> {
        self.ports.get(name).or_else(|| {
            self.type_aliases.iter().find_map(|(alias_name, alias)| {
                (trait_object_principal(&alias.ty).as_deref() == Some(name))
                    .then(|| self.ports.get(alias_name))
                    .flatten()
            })
        })
    }
}

impl PortClass {
    fn at_field(&self, subject: &str) -> Self {
        Self {
            effect: self.effect.clone(),
            privilege: self.privilege.clone(),
            subject: subject.to_string(),
            port: format!("{} (classified at {})", self.port, self.subject),
            privilege_subject: subject.to_string(),
            privilege_port: format!(
                "{} (classified at {})",
                self.privilege_port, self.privilege_subject
            ),
        }
    }
}

fn collect_items(items: &[Item], subject: &str, owner: &str, out: &mut OwnerSource) -> Result<()> {
    for item in items {
        if !attrs_are_production(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Struct(item) => collect_struct(item, subject, &mut out.structs)?,
            Item::Impl(item) => collect_state_impl(item, subject, &mut out.states)?,
            Item::Macro(item) => collect_port_macro(
                item,
                subject,
                owner,
                &out.trusted_port_macros,
                &mut out.ports,
            )?,
            Item::Type(item) => collect_type_alias(item, subject, &mut out.type_aliases)?,
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_items(nested, subject, owner, out)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_type_alias(
    item: &ItemType,
    subject: &str,
    out: &mut BTreeMap<String, TypeAlias>,
) -> Result<()> {
    let name = item.ident.to_string();
    let alias = TypeAlias {
        ty: (*item.ty).clone(),
        params: item
            .generics
            .type_params()
            .map(|param| param.ident.to_string())
            .collect(),
        subject: source_at(subject, item.span()),
    };
    if out.insert(name.clone(), alias).is_some() {
        bail!("duplicate type alias `{name}`");
    }
    Ok(())
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
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
    }
}

fn collect_struct(
    item: &ItemStruct,
    subject: &str,
    out: &mut BTreeMap<String, StructInfo>,
) -> Result<()> {
    let name = item.ident.to_string();
    let named_fields: BTreeMap<_, _> = item
        .fields
        .iter()
        .filter(|field| crate::localtx_coverage::attrs_may_be_production(&field.attrs))
        .filter_map(|field| {
            Some((
                field.ident.as_ref()?.to_string(),
                terminal_type_ident(&field.ty)?,
            ))
        })
        .collect();
    let fields = item
        .fields
        .iter()
        .filter(|field| crate::localtx_coverage::attrs_may_be_production(&field.attrs))
        .map(|field| StructField {
            ty: field.ty.clone(),
            subject: source_at(subject, field.span()),
        })
        .collect();
    if out
        .insert(
            name.clone(),
            StructInfo {
                fields,
                named_fields,
                subject: source_at(subject, item.span()),
            },
        )
        .is_some()
    {
        bail!("duplicate struct identity `{name}` in owner source");
    }
    Ok(())
}

fn collect_state_impl(
    item: &ItemImpl,
    subject: &str,
    out: &mut BTreeMap<String, StateImpl>,
) -> Result<()> {
    let Some((_, trait_path, _)) = &item.trait_ else {
        return Ok(());
    };
    if trait_path
        .segments
        .last()
        .is_none_or(|segment| segment.ident != "ClassifiedRouteState")
    {
        return Ok(());
    }
    let Type::Path(self_ty) = item.self_ty.as_ref() else {
        return Ok(());
    };
    let Some(name) = self_ty
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return Ok(());
    };
    let mut effect = None;
    let mut privilege = None;
    for impl_item in &item.items {
        if let ImplItem::Type(assoc) = impl_item {
            let value = terminal_type_ident(&assoc.ty);
            if assoc.ident == "Effect" {
                effect = value;
            } else if assoc.ident == "Privilege" {
                privilege = value;
            }
        }
    }
    let state = StateImpl {
        effect: effect.ok_or_else(|| anyhow!("{subject}: `{name}` missing Effect"))?,
        privilege: privilege.ok_or_else(|| anyhow!("{subject}: `{name}` missing Privilege"))?,
        subject: source_at(subject, item.span()),
    };
    if out.insert(name.clone(), state).is_some() {
        bail!("duplicate ClassifiedRouteState impl for `{name}`");
    }
    Ok(())
}

fn collect_port_macro(
    item: &syn::ItemMacro,
    subject: &str,
    owner: &str,
    trusted: &BTreeSet<String>,
    out: &mut BTreeMap<String, PortClass>,
) -> Result<()> {
    let canonical_subject = format!("crates/{owner}/src/ports.rs");
    if subject != canonical_subject {
        return Ok(());
    }
    let name = item
        .mac
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    let canonical_plural = format!("classify_{}_ports", owner.replace('-', "_"));
    let canonical_singular = format!("classify_{}_port", owner.replace('-', "_"));
    if name != canonical_plural && name != canonical_singular {
        return Ok(());
    }
    if !trusted.contains(&name) {
        bail!("owner port classification invocation `{name}` is not bound to its canonical macro");
    }
    let text = item.mac.tokens.to_string();
    if name.ends_with("_ports") {
        for entry in text.split([',', ';']) {
            let words = identifiers(entry);
            if let (Some(port), Some(effect)) = (
                words.iter().find(|word| word.starts_with("Dyn")),
                words.iter().find(|word| word.ends_with("Effect")),
            ) {
                insert_port(
                    out,
                    port,
                    effect,
                    "LocalPrivilege",
                    &source_at(subject, item.span()),
                )?;
            }
        }
    } else {
        let words = identifiers(&text);
        if let (Some(port), Some(effect), Some(privilege)) = (
            words.iter().find(|word| word.starts_with("Dyn")),
            words.iter().find(|word| word.ends_with("Effect")),
            words.iter().find(|word| word.ends_with("Privilege")),
        ) {
            insert_port(
                out,
                port,
                effect,
                privilege,
                &source_at(subject, item.span()),
            )?;
        }
    }
    Ok(())
}

fn collect_trusted_port_macro_definitions(
    items: &[Item],
    subject: &str,
    owner: &str,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    if subject != format!("crates/{owner}/src/ports.rs") {
        return Ok(());
    }
    let expected = [
        format!("classify_{}_ports", owner.replace('-', "_")),
        format!("classify_{}_port", owner.replace('-', "_")),
    ];
    for item in items {
        let Item::Macro(item) = item else {
            continue;
        };
        let Some(name) = item.ident.as_ref().map(ToString::to_string) else {
            continue;
        };
        if !expected.contains(&name) {
            continue;
        }
        let words = identifiers(&item.mac.tokens.to_string());
        for required in ["Sealed", "PortEffectClass", "assert_effect"] {
            if !words.iter().any(|word| word == required) {
                bail!("canonical owner port classification macro `{name}` has opaque semantics");
            }
        }
        if !out.insert(name.clone()) {
            bail!("duplicate canonical owner port macro `{name}`");
        }
    }
    Ok(())
}

fn insert_port(
    out: &mut BTreeMap<String, PortClass>,
    port: &str,
    effect: &str,
    privilege: &str,
    subject: &str,
) -> Result<()> {
    let class = PortClass {
        effect: effect.to_string(),
        privilege: privilege.to_string(),
        subject: subject.to_string(),
        port: port.to_string(),
        privilege_subject: subject.to_string(),
        privilege_port: port.to_string(),
    };
    if out.insert(port.to_string(), class).is_some() {
        bail!("duplicate owner port classification `{port}`");
    }
    Ok(())
}

fn collect_diport_capabilities(root: &Path, out: &mut BTreeMap<String, PortClass>) -> Result<()> {
    let effect = root.join("crates/diport/src/effect.rs");
    let file = if effect.is_file() {
        effect
    } else {
        root.join("crates/diport/src/lib.rs")
    };
    let subject = relative(root, &file)?;
    let syntax = syn::parse_file(
        &std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?,
    )
    .with_context(|| format!("parse `{subject}`"))?;
    let mut found = false;
    for item in syntax.items {
        let Item::Macro(item) = item else {
            continue;
        };
        if item
            .mac
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "classify_ports")
        {
            continue;
        }
        found = true;
        let location = source_at(&subject, item.span());
        for entry in item.mac.tokens.to_string().split(';') {
            let words = identifiers(entry);
            let Some(kind) = words.first().map(String::as_str) else {
                continue;
            };
            if !matches!(kind, "dyn" | "sync") {
                bail!("{location}: opaque diport capability classification entry");
            }
            let port = words
                .get(1)
                .ok_or_else(|| anyhow!("{location}: missing diport capability name"))?;
            let effect = words
                .iter()
                .find(|word| word.ends_with("Effect"))
                .ok_or_else(|| anyhow!("{location}: missing diport capability effect"))?;
            insert_port(out, port, effect, "LocalPrivilege", &location)?;
        }
    }
    if !found {
        bail!("{subject}: canonical owner-sealed `classify_ports!` table is missing");
    }
    Ok(())
}

fn type_arguments(arguments: &PathArguments) -> Vec<Type> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return Vec::new();
    };
    arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            GenericArgument::Type(ty) => Some(ty.clone()),
            GenericArgument::AssocType(assoc) => Some(assoc.ty.clone()),
            _ => None,
        })
        .collect()
}

fn trait_object_principal(ty: &Type) -> Option<String> {
    let Type::TraitObject(object) = ty else {
        return None;
    };
    let principals: Vec<_> = object
        .bounds
        .iter()
        .filter_map(|bound| match bound {
            TypeParamBound::Trait(bound) => bound
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        })
        .filter(|name| !matches!(name.as_str(), "Send" | "Sync" | "Unpin"))
        .collect();
    (principals.len() == 1).then(|| principals[0].clone())
}

fn source_at(subject: &str, span: proc_macro2::Span) -> String {
    format!("{subject}:{}", span.start().line)
}

fn diagnostic_source(detail: &str) -> Option<String> {
    let start = detail.find("crates/")?;
    let candidate = &detail[start..];
    let line_separator = candidate.find(':')?;
    let after = &candidate[line_separator + 1..];
    let line_end = after.find(':')?;
    after[..line_end]
        .chars()
        .all(|character| character.is_ascii_digit())
        .then(|| candidate[..line_separator + line_end + 1].to_string())
}

fn state_expr_name(expr: &Expr, bindings: &BTreeMap<String, String>) -> Option<String> {
    match peel_expr(expr) {
        Expr::Struct(value) => value
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::Path(value) => value
            .path
            .segments
            .last()
            .and_then(|segment| bindings.get(&segment.ident.to_string()).cloned()),
        Expr::MethodCall(value) if value.method == "clone" => {
            state_expr_name(&value.receiver, bindings)
        }
        _ => None,
    }
}

fn binding_types(
    file: &syn::File,
    structs: &BTreeMap<String, StructInfo>,
) -> BTreeMap<String, String> {
    struct Locals(Vec<(String, Expr)>);
    impl<'ast> Visit<'ast> for Locals {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if attrs_are_production(&node.attrs)
                && let syn::Pat::Ident(pattern) = &node.pat
                && pattern.subpat.is_none()
                && let Some(init) = &node.init
            {
                self.0
                    .push((pattern.ident.to_string(), (*init.expr).clone()));
            }
            visit::visit_local(self, node);
        }
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if attrs_are_production(&node.attrs) {
                visit::visit_item_mod(self, node);
            }
        }
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if attrs_are_production(&node.attrs) {
                visit::visit_item_fn(self, node);
            }
        }
    }
    let mut locals = Locals(Vec::new());
    locals.visit_file(file);
    let mut fields = BTreeMap::new();
    let mut duplicate_fields = BTreeSet::new();
    for info in structs.values() {
        for (field, ty) in &info.named_fields {
            if fields.insert(field.clone(), ty.clone()).is_some() {
                duplicate_fields.insert(field.clone());
            }
        }
    }
    for field in duplicate_fields {
        fields.remove(&field);
    }
    let mut out = BTreeMap::new();
    for _ in 0..8 {
        let before = out.len();
        for (name, expr) in &locals.0 {
            if let Some(ty) = initializer_type(expr, &out, &fields) {
                out.insert(name.clone(), ty);
            }
        }
        if out.len() == before {
            break;
        }
    }
    out
}

fn initializer_type(
    expr: &Expr,
    bindings: &BTreeMap<String, String>,
    fields: &BTreeMap<String, String>,
) -> Option<String> {
    match peel_expr(expr) {
        Expr::Struct(value) => value
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::Path(value) => value
            .path
            .segments
            .last()
            .and_then(|segment| bindings.get(&segment.ident.to_string()).cloned()),
        Expr::MethodCall(value) if value.method == "clone" => {
            initializer_type(&value.receiver, bindings, fields)
        }
        Expr::Call(value) => {
            if let Expr::Path(function) = peel_expr(&value.func)
                && function
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "new")
                && let Some(owner) = function.path.segments.iter().rev().nth(1)
            {
                Some(owner.ident.to_string())
            } else {
                value
                    .args
                    .first()
                    .and_then(|arg| initializer_type(arg, bindings, fields))
            }
        }
        Expr::Field(value) => match &value.member {
            syn::Member::Named(field) => fields.get(&field.to_string()).cloned(),
            syn::Member::Unnamed(_) => None,
        },
        _ => None,
    }
}

fn generated_localonly_routes(root: &Path) -> Result<BTreeSet<String>> {
    let dir = root.join("generated/src/http");
    let mut routes = BTreeSet::new();
    for file in rust_files(&dir)? {
        if file.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
            continue;
        }
        let module = file
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("generated module filename is not UTF-8"))?;
        let syntax = syn::parse_file(&std::fs::read_to_string(&file)?)?;
        collect_generated_routes(&syntax.items, module, &mut Vec::new(), &mut routes)?;
    }
    Ok(routes)
}

fn collect_generated_routes(
    items: &[Item],
    module: &str,
    nested: &mut Vec<String>,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    for item in items {
        match item {
            Item::Const(item) if item.ident == "ROUTE" && route_type_is_localonly(&item.ty) => {
                let key = std::iter::once(module.to_string())
                    .chain(nested.iter().cloned())
                    .collect::<Vec<_>>()
                    .join("::");
                if !out.insert(key.clone()) {
                    bail!("duplicate generated LocalOnly ROUTE `{key}`");
                }
            }
            Item::Mod(item) => {
                if let Some((_, children)) = &item.content {
                    nested.push(item.ident.to_string());
                    collect_generated_routes(children, module, nested, out)?;
                    nested.pop();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn route_type_is_localonly(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    let Some(binding) = path.path.segments.last() else {
        return false;
    };
    if binding.ident != "HttpRouteBinding" {
        return false;
    }
    let PathArguments::AngleBracketed(args) = &binding.arguments else {
        return false;
    };
    matches!(args.args.iter().nth(1), Some(GenericArgument::Type(Type::Path(marker))) if marker.path.segments.last().is_some_and(|segment| segment.ident == "LocalOnly"))
}

fn terminal_type_ident(ty: &Type) -> Option<String> {
    struct LastIdent(Vec<String>);
    impl<'ast> Visit<'ast> for LastIdent {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            for segment in &node.path.segments {
                let ident = segment.ident.to_string();
                if !matches!(ident.as_str(), "Arc" | "Box" | "Option" | "Vec") {
                    self.0.push(ident);
                }
                visit::visit_path_arguments(self, &segment.arguments);
            }
        }
    }
    let mut visitor = LastIdent(Vec::new());
    visitor.visit_type(ty);
    visitor
        .0
        .iter()
        .rev()
        .find(|ident| ident.starts_with("Dyn"))
        .cloned()
        .or_else(|| visitor.0.last().cloned())
}

fn identifiers(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn effect_rank(effect: &str) -> u8 {
    match effect {
        "AuthEffect" => 0,
        "ReadEffect" => 1,
        "WriteEffect" => 2,
        "OutboxEffect" => 3,
        "WorkflowEffect" => 4,
        _ => 255,
    }
}

fn attrs_are_production(attrs: &[syn::Attribute]) -> bool {
    !attrs.iter().any(|attr| attr.path().is_ident("test"))
        && crate::localtx_coverage::attrs_may_be_production(attrs)
}

fn peel_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(value) => peel_expr(&value.expr),
        Expr::Paren(value) => peel_expr(&value.expr),
        Expr::Group(value) => peel_expr(&value.expr),
        other => other,
    }
}

fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("read `{}`", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("symlink source evidence is forbidden");
            }
            if kind.is_dir() {
                walk(&path, files)?;
            } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs")
            {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(dir, &mut files)?;
    files.sort();
    Ok(files)
}

#[allow(clippy::too_many_arguments)]
fn contract_finding(
    rule: Rule,
    id: &str,
    method: &str,
    path: &str,
    subject: &str,
    effect: &str,
    privilege: &str,
    source: &str,
) -> Finding {
    finding(
        rule,
        subject.to_string(),
        format!(
            "contract `{id}` {method} {path}: state=`{subject}` port=`{source}` effect=`{effect}` privilege=`{privilege}`"
        ),
    )
}

fn classified_finding(rule: Rule, contract: &Contract, state: &str, class: &PortClass) -> Finding {
    let (subject, port) = if matches!(rule, Rule::CrossTenantPrivilege) {
        (&class.privilege_subject, &class.privilege_port)
    } else {
        (&class.subject, &class.port)
    };
    finding(
        rule,
        subject.clone(),
        format!(
            "contract `{}` {} {}: state=`{state}` port=`{}` effect=`{}` privilege=`{}`",
            contract.id, contract.method, contract.path, port, class.effect, class.privilege
        ),
    )
}

fn relative_manifest_path(root: &Path, contract: &DiscoveredContract) -> Result<String> {
    relative(root, &contract.dir.join("contract.toml"))
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path outside workspace"))?
        .to_str()
        .ok_or_else(|| anyhow!("path is not UTF-8"))?
        .replace('\\', "/"))
}
fn required_path<'a>(path: Option<&'a str>, subject: &str, id: &str) -> Result<&'a str> {
    path.ok_or_else(|| anyhow!("{subject}: active LocalOnly HTTP contract `{id}` missing `path`"))
}
fn required_method(method: Option<HttpMethod>, subject: &str, id: &str) -> Result<HttpMethod> {
    method
        .ok_or_else(|| anyhow!("{subject}: active LocalOnly HTTP contract `{id}` missing `method`"))
}
fn generated_key(domain: &str, version: &str, slug: Option<&str>) -> String {
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    slug.map_or(module.clone(), |slug| {
        format!("{module}::{}", slug.replace('-', "_"))
    })
}
fn forbidden_effect_wire(effect: EffectKind) -> Option<&'static str> {
    match effect {
        EffectKind::Auth | EffectKind::Read | EffectKind::Projection => None,
        EffectKind::Write => Some("write"),
        EffectKind::Transaction => Some("transaction"),
        EffectKind::Outbox => Some("outbox"),
        EffectKind::Publish => Some("publish"),
        EffectKind::Workflow => Some("workflow"),
        EffectKind::Saga => Some("saga"),
        EffectKind::Reconcile => Some("reconcile"),
        EffectKind::Worker => Some("worker"),
        EffectKind::CrossTenantAudit => Some("cross-tenant-audit"),
    }
}
fn sanitized(root: &Path, error: anyhow::Error) -> anyhow::Error {
    anyhow!(format!("{error:#}").replace(root.to_string_lossy().as_ref(), "."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/consistency_effects")
            .join(name)
    }

    struct WorkspaceFixture(PathBuf);

    impl WorkspaceFixture {
        fn new() -> Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "rss-consistency-effects-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            copy_tree(&fixture("workspace"), &path)?;
            Ok(Self(path))
        }

        fn source(&self) -> PathBuf {
            self.0.join("crates/demo/src/lib.rs")
        }
        fn ports(&self) -> PathBuf {
            self.0.join("crates/demo/src/ports.rs")
        }
        fn replace(&self, file: &Path, from: &str, to: &str) -> Result<()> {
            let text = fs::read_to_string(file)?;
            if !text.contains(from) {
                bail!("fixture mutation source is missing: {from}");
            }
            fs::write(file, text.replacen(from, to, 1))?;
            Ok(())
        }

        fn cargo_check(&self) -> Result<std::process::Output> {
            let target = self.0.join("target");
            crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Check,
                &["--offline"],
                &[(
                    "CARGO_TARGET_DIR",
                    target
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture target path is not UTF-8"))?,
                )],
                Some(&self.0),
            )
            .arg("--manifest-path")
            .arg(self.0.join("Cargo.toml"))
            .output()
            .map_err(Into::into)
        }

        fn assert_compiles_and_is_rejected(&self) -> Result<Vec<Finding>> {
            let output = self.cargo_check()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let findings = check_root(&self.0)?.1;
            assert!(
                !findings.is_empty(),
                "compiling red fixture unexpectedly passed"
            );
            Ok(findings)
        }

        fn add_write_port(&self) -> Result<()> {
            self.replace(
                &self.ports(),
                "pub type DynReadRepo = dyn ReadRepo;",
                "pub type DynReadRepo = dyn ReadRepo; pub trait WriteRepo: Send + Sync {} pub type DynWriteRepo = dyn WriteRepo;",
            )?;
            self.replace(
                &self.ports(),
                "classify_demo_ports!(DynReadRepo => diport::ReadEffect);",
                "classify_demo_ports!(DynReadRepo => diport::ReadEffect); classify_demo_ports!(DynWriteRepo => diport::WriteEffect);",
            )
        }
    }

    impl Drop for WorkspaceFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn copy_tree(source: &Path, target: &Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let destination = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &destination)?;
            } else {
                fs::copy(entry.path(), destination)?;
            }
        }
        Ok(())
    }

    fn provenance_findings(source: &str) -> Result<Vec<Finding>> {
        let syntax = syn::parse_file(source)?;
        let mut recorded_provider_fields = BTreeMap::new();
        collect_recorded_provider_fields(&syntax.items, &mut recorded_provider_fields);
        let mut findings = Vec::new();
        provenance_findings_in_items(
            &syntax.items,
            "crates/demo/src/lib.rs",
            &recorded_provider_fields,
            &mut findings,
        );
        Ok(findings)
    }

    const GOVERNED_PROVENANCE: &str = r#"
struct Repo { counter: Counter }
impl Repo {
    fn default() -> Self { todo!() }
    fn test_repo(&self) -> TestRepo { todo!() }
    fn mutate(&self) { self.counter.record(); }
}
fn conforms() {
    let repo_probe = Repo::default();
    let router = finalized_scoped_router(repo_probe.test_repo());
    let proof = ::httpserve::prove_local_only_state::<ReadState>();
    let outbox = ::testkit::local_only::StaticExclusion::<Outbox>::from_governed(&proof);
    let publish = ::testkit::local_only::StaticExclusion::<Publish>::from_governed(&proof);
    let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);
    let _response = router.oneshot();
}
"#;

    #[test]
    fn governed_observation_provenance_is_accepted() -> Result<()> {
        let findings = provenance_findings(GOVERNED_PROVENANCE)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let stateless = GOVERNED_PROVENANCE.replace(
            "::httpserve::prove_local_only_state::<ReadState>()",
            "::httpserve::prove_stateless_local_only_route(&PROFILE_HTTP_ROUTE)",
        );
        let findings = provenance_findings(&stateless)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn forged_observation_provenance_is_rejected() -> Result<()> {
        let cases = [
            (
                "legacy owner trait",
                GOVERNED_PROVENANCE.replace(
                    "struct Repo { counter: Counter }",
                    "impl StaticExclusionOwner<Write> for Fake {}\nstruct Repo { counter: Counter }",
                ),
            ),
            (
                "legacy runtime closure",
                GOVERNED_PROVENANCE.replace(
                    "repo_probe.counter.handle()",
                    "RuntimeProbe::write(|| 0)",
                ),
            ),
            (
                "inline proof",
                GOVERNED_PROVENANCE.replace(
                    "::testkit::local_only::StaticExclusion::<Outbox>::from_governed(&proof)",
                    "::testkit::local_only::StaticExclusion::<Outbox>::from_governed(&::httpserve::prove_local_only_state::<ReadState>())",
                ),
            ),
            (
                "forged proof binding",
                GOVERNED_PROVENANCE.replace(
                    "let proof = ::httpserve::prove_local_only_state::<ReadState>();",
                    "let proof = FakeProof::new();",
                ),
            ),
            (
                "lookalike proof constructor",
                GOVERNED_PROVENANCE.replace(
                    "::httpserve::prove_local_only_state::<ReadState>()",
                    "::lookalike::prove_local_only_state::<ReadState>()",
                ),
            ),
            (
                "decoy provider",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let decoy = Repo::default();\n    let _observers = ::testkit::local_only::LocalOnlyObservers::new(decoy.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "provider misses mutation record",
                GOVERNED_PROVENANCE.replace("self.counter.record();", "drop(&self.counter);"),
            ),
            (
                "decoy field records instead of observed field",
                GOVERNED_PROVENANCE.replace("self.counter.record();", "self.decoy.record();"),
            ),
            (
                "provider alias hides origin",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let provider_alias = &repo_probe;\n    let _observers = ::testkit::local_only::LocalOnlyObservers::new(provider_alias.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "opaque handle parameter",
                GOVERNED_PROVENANCE
                    .replace(
                        "fn conforms()",
                        "fn conforms(input_handle: ProviderCounterHandle<Write>)",
                    )
                    .replace("repo_probe.counter.handle()", "input_handle"),
            ),
            (
                "import-style observer alias",
                GOVERNED_PROVENANCE.replace(
                    "::testkit::local_only::LocalOnlyObservers::new",
                    "LocalOnlyObservers::new",
                ),
            ),
            (
                "observer function item constructor",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let ctor = ::testkit::local_only::LocalOnlyObservers::new;\n    let _observers = ctor(repo_probe.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "shadowed absolute-looking proof namespace",
                GOVERNED_PROVENANCE.replace(
                    "::httpserve::prove_local_only_state::<ReadState>()",
                    "::evil::httpserve::prove_local_only_state::<ReadState>()",
                ),
            ),
            (
                "bait test repo call",
                GOVERNED_PROVENANCE.replace(
                    "let router = finalized_scoped_router(repo_probe.test_repo());",
                    "let _bait = repo_probe.test_repo();\n    let router = finalized_scoped_router(other_probe.test_repo());",
                ),
            ),
            (
                "bait oneshot call",
                GOVERNED_PROVENANCE.replace(
                    "let _response = router.oneshot();",
                    "let _response = bait_router.oneshot();",
                ),
            ),
        ];
        for (name, source) in cases {
            let findings = provenance_findings(&source)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| matches!(finding.rule, Rule::ForgedObservationEvidence)),
                "{name} unexpectedly passed: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn provenance_inventory_includes_non_crates_workspace_members() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let manifest = workspace.0.join("Cargo.toml");
        workspace.replace(
            &manifest,
            ", \"generated\"]",
            ", \"generated\", \"tools/consumer\"]",
        )?;
        let consumer = workspace.0.join("tools/consumer");
        fs::create_dir_all(consumer.join("src"))?;
        fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        fs::write(
            consumer.join("src/lib.rs"),
            "struct RuntimeProbe; impl RuntimeProbe { fn write(_: impl Fn() -> u64) {} } fn bait() { RuntimeProbe::write(|| 0); }\n",
        )?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let findings = check_root(&workspace.0)?.1;
        assert!(findings.iter().any(|finding| {
            matches!(finding.rule, Rule::ForgedObservationEvidence)
                && finding.subject.starts_with("tools/consumer/src/lib.rs:")
        }));
        Ok(())
    }

    #[test]
    fn safe_profiles_pass_and_inactive_or_non_localonly_are_ignored() -> Result<()> {
        let (summary, findings) = check_root(&fixture("green"))?;
        assert_eq!(summary, "1 active LocalOnly HTTP contract(s) checked");
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn forbidden_profiles_are_stable_and_closed() -> Result<()> {
        let (_, findings) = check_root(&fixture("all_forbidden"))?;
        assert_eq!(findings.len(), 9);
        assert!(
            findings
                .iter()
                .all(|finding| matches!(finding.rule, Rule::ForbiddenStateEffect))
        );
        let details: Vec<_> = findings
            .iter()
            .map(|finding| finding.detail.as_str())
            .collect();
        assert!(details.windows(2).all(|pair| pair[0] <= pair[1]));
        Ok(())
    }

    #[test]
    fn incomplete_metadata_is_a_hard_error() {
        for fixture_name in [
            "missing_profile",
            "missing_kind",
            "missing_path",
            "missing_method",
        ] {
            assert!(
                check_root(&fixture(fixture_name)).is_err(),
                "{fixture_name}"
            );
        }
    }

    #[test]
    fn strongest_effect_ranking_is_fail_closed() {
        assert!(effect_rank("BogusEffect") > effect_rank("WorkflowEffect"));
        assert!(effect_rank("WorkflowEffect") > effect_rank("WriteEffect"));
    }

    #[test]
    fn same_named_fake_classification_macro_is_not_canonical() -> Result<()> {
        let syntax: syn::File =
            syn::parse_str("macro_rules! classify_demo_ports { ($($tokens:tt)*) => {}; }")?;
        let mut trusted = BTreeSet::new();
        assert!(
            collect_trusted_port_macro_definitions(
                &syntax.items,
                "crates/demo/src/ports.rs",
                "demo",
                &mut trusted,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn state_classification_rejects_strongest_effect_lies() {
        let source = OwnerSource {
            states: BTreeMap::from([(
                "ReadState".to_string(),
                StateImpl {
                    effect: "ReadEffect".to_string(),
                    privilege: "LocalPrivilege".to_string(),
                    subject: "crates/demo/src/lib.rs:2".to_string(),
                },
            )]),
            structs: BTreeMap::from([(
                "ReadState".to_string(),
                StructInfo {
                    fields: vec![StructField {
                        ty: syn::parse_quote!(DynWriter),
                        subject: "crates/demo/src/lib.rs:1".to_string(),
                    }],
                    named_fields: BTreeMap::from([("repo".to_string(), "DynWriter".to_string())]),
                    subject: "crates/demo/src/lib.rs:1".to_string(),
                },
            )]),
            ports: BTreeMap::from([(
                "DynWriter".to_string(),
                PortClass {
                    effect: "WriteEffect".to_string(),
                    privilege: "LocalPrivilege".to_string(),
                    subject: "crates/demo/src/ports.rs".to_string(),
                    port: "DynWriter".to_string(),
                    privilege_subject: "crates/demo/src/ports.rs".to_string(),
                    privilege_port: "DynWriter".to_string(),
                },
            )]),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        assert!(source.classify_state("ReadState").is_err());
    }

    #[test]
    fn composite_state_aggregates_strongest_effect_and_cross_tenant_privilege() -> Result<()> {
        let source = OwnerSource {
            states: BTreeMap::from([(
                "State".to_string(),
                StateImpl {
                    effect: "WriteEffect".to_string(),
                    privilege: "CrossTenantPrivilege".to_string(),
                    subject: "crates/demo/src/lib.rs:4".to_string(),
                },
            )]),
            structs: BTreeMap::from([(
                "State".to_string(),
                StructInfo {
                    fields: vec![StructField {
                        ty: syn::parse_quote!((DynWriter, DynAdmin)),
                        subject: "crates/demo/src/lib.rs:2".to_string(),
                    }],
                    named_fields: BTreeMap::new(),
                    subject: "crates/demo/src/lib.rs:1".to_string(),
                },
            )]),
            ports: BTreeMap::from([
                (
                    "DynWriter".to_string(),
                    PortClass {
                        effect: "WriteEffect".to_string(),
                        privilege: "LocalPrivilege".to_string(),
                        subject: "crates/demo/src/ports.rs:10".to_string(),
                        port: "DynWriter".to_string(),
                        privilege_subject: "crates/demo/src/ports.rs:10".to_string(),
                        privilege_port: "DynWriter".to_string(),
                    },
                ),
                (
                    "DynAdmin".to_string(),
                    PortClass {
                        effect: "ReadEffect".to_string(),
                        privilege: "CrossTenantPrivilege".to_string(),
                        subject: "crates/demo/src/ports.rs:11".to_string(),
                        port: "DynAdmin".to_string(),
                        privilege_subject: "crates/demo/src/ports.rs:11".to_string(),
                        privilege_port: "DynAdmin".to_string(),
                    },
                ),
            ]),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        let class = source.classify_state("State")?;
        assert_eq!(class.effect, "WriteEffect");
        assert_eq!(class.privilege, "CrossTenantPrivilege");
        Ok(())
    }

    #[test]
    fn cfg_feature_named_contest_is_not_mistaken_for_cfg_test() -> Result<()> {
        let syntax: syn::File = syn::parse_str("#[cfg(feature = \"contest\")] fn live() {}")?;
        let Item::Fn(function) = &syntax.items[0] else {
            bail!("fixture must be a function");
        };
        assert!(attrs_are_production(&function.attrs));
        Ok(())
    }

    #[test]
    fn complete_green_workspace_compiles_and_closes_the_canonical_mount() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (summary, findings) = check_root(&workspace.0)?;
        assert_eq!(summary, "1 active LocalOnly HTTP contract(s) checked");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn canonical_mount_and_state_red_matrix_is_fail_closed() -> Result<()> {
        let cases = [
            (
                "ordinary",
                ".with_classified_state(state)",
                ".with_state(state)",
            ),
            (
                "unclassified",
                "impl ::httpserve::ClassifiedRouteState for ReadState",
                "impl Unrelated for ReadState",
            ),
            (
                "non-domain",
                "impl ::bootstrap::Domain for Demo",
                "impl Demo",
            ),
            (
                "cfg-disabled",
                "impl ::bootstrap::Domain for Demo",
                "#[cfg(test)] impl ::bootstrap::Domain for Demo",
            ),
            ("unmounted", "Ok(router.mount(", "Ok(router.fake_mount("),
        ];
        for (name, from, to) in cases {
            let workspace = WorkspaceFixture::new()?;
            workspace.replace(&workspace.source(), from, to)?;
            assert!(
                !check_root(&workspace.0)?.1.is_empty(),
                "{name} unexpectedly passed"
            );
        }
        Ok(())
    }

    #[test]
    fn alias_strongest_effect_and_fake_macro_are_rejected() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        workspace.replace(
            &workspace.ports(),
            "pub type DynReadRepo = dyn ReadRepo;",
            "pub type DynReadRepo = dyn ReadRepo; pub trait WriteRepo: Send + Sync {} pub type DynWriteRepo = dyn WriteRepo;",
        )?;
        workspace.replace(
            &workspace.ports(),
            "classify_demo_ports!(DynReadRepo => diport::ReadEffect);",
            "classify_demo_ports!(DynReadRepo => diport::ReadEffect); classify_demo_ports!(DynWriteRepo => diport::WriteEffect);",
        )?;
        workspace.replace(
            &workspace.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type HiddenWriter = Arc<ports::DynWriteRepo>; struct ReadState { repo: Arc<DynReadRepo>, hidden: HiddenWriter }",
        )?;
        workspace.replace(
            &workspace.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        let findings = check_root(&workspace.0)?.1;
        assert!(
            findings
                .iter()
                .any(|item| matches!(item.rule, Rule::OpaqueSourceScope))
        );

        let fake = WorkspaceFixture::new()?;
        fake.replace(
            &fake.ports(),
            "macro_rules! classify_demo_ports {",
            "macro_rules! classify_demo_ports_fake {",
        )?;
        assert!(
            check_root(&fake.0).is_err(),
            "same-shaped fake macro must fail closed"
        );
        Ok(())
    }

    #[test]
    fn composite_capability_leaves_are_order_independent_and_fail_closed() -> Result<()> {
        for field_ty in [
            "(Arc<DynReadRepo>, Arc<ports::DynWriteRepo>)",
            "(Arc<ports::DynWriteRepo>, Arc<DynReadRepo>)",
            "Option<Vec<[Arc<ports::DynWriteRepo>; 1]>>",
            "&'static Arc<ports::DynWriteRepo>",
        ] {
            let workspace = WorkspaceFixture::new()?;
            workspace.add_write_port()?;
            workspace.replace(
                &workspace.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!("struct ReadState {{ repo: Arc<DynReadRepo>, hidden: {field_ty} }}"),
            )?;
            workspace.replace(
                &workspace.source(),
                "ReadState { repo: unimplemented!() }",
                "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
            )?;
            workspace.assert_compiles_and_is_rejected()?;
        }

        let alias = WorkspaceFixture::new()?;
        alias.add_write_port()?;
        alias.replace(
            &alias.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type Hidden = (Arc<DynReadRepo>, Arc<ports::DynWriteRepo>); struct ReadState { repo: Arc<DynReadRepo>, hidden: Hidden }",
        )?;
        alias.replace(
            &alias.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        alias.assert_compiles_and_is_rejected()?;

        let generic_alias = WorkspaceFixture::new()?;
        generic_alias.add_write_port()?;
        generic_alias.replace(
            &generic_alias.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type Hidden<T> = (T, Option<Arc<ports::DynWriteRepo>>); struct ReadState { repo: Arc<DynReadRepo>, hidden: Hidden<Arc<DynReadRepo>> }",
        )?;
        generic_alias.replace(
            &generic_alias.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        generic_alias.assert_compiles_and_is_rejected()?;
        Ok(())
    }

    #[test]
    fn sync_diport_and_unknown_trait_objects_are_fail_closed() -> Result<()> {
        for capability in [
            "Arc<dyn diport::SubscribeInitializer>",
            "Arc<diport::DynSubscriber<'static>>",
        ] {
            let workflow = WorkspaceFixture::new()?;
            workflow.replace(
                &workflow.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!(
                    "struct ReadState {{ repo: Arc<DynReadRepo>, subscription: {capability} }}"
                ),
            )?;
            workflow.replace(
                &workflow.source(),
                "ReadState { repo: unimplemented!() }",
                "ReadState { repo: unimplemented!(), subscription: unimplemented!() }",
            )?;
            workflow.assert_compiles_and_is_rejected()?;
        }

        let unknown = WorkspaceFixture::new()?;
        unknown.replace(
            &unknown.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "trait UnknownCapability: Send + Sync {} struct ReadState { repo: Arc<DynReadRepo>, unknown: Arc<dyn UnknownCapability> }",
        )?;
        unknown.replace(
            &unknown.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), unknown: unimplemented!() }",
        )?;
        unknown.assert_compiles_and_is_rejected()?;
        Ok(())
    }

    #[test]
    fn production_cfg_boolean_semantics_cannot_hide_capabilities() -> Result<()> {
        for cfg in [
            "not(test)",
            "any(test, not(test))",
            "all(not(test), any())",
            "feature = \"production_possible\"",
        ] {
            let workspace = WorkspaceFixture::new()?;
            workspace.add_write_port()?;
            workspace.replace(
                &workspace.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!(
                    "struct ReadState {{ repo: Arc<DynReadRepo>, #[cfg({cfg})] hidden: Arc<ports::DynWriteRepo> }}"
                ),
            )?;
            workspace.replace(
                &workspace.source(),
                "ReadState { repo: unimplemented!() }",
                &format!(
                    "ReadState {{ repo: unimplemented!(), #[cfg({cfg})] hidden: unimplemented!() }}"
                ),
            )?;
            let output = workspace.cargo_check()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let findings = check_root(&workspace.0)?.1;
            if cfg != "all(not(test), any())" {
                assert!(!findings.is_empty(), "cfg({cfg}) unexpectedly hid a writer");
            } else {
                assert!(findings.is_empty(), "cfg({cfg}) is constantly false");
            }
        }
        Ok(())
    }

    #[test]
    fn forbidden_diagnostic_preserves_contract_and_field_provenance() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        workspace.add_write_port()?;
        workspace.replace(
            &workspace.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "struct ReadState { repo: Arc<DynReadRepo>, hidden: Arc<ports::DynWriteRepo> }",
        )?;
        workspace.replace(
            &workspace.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        let findings = workspace.assert_compiles_and_is_rejected()?;
        let finding = findings
            .iter()
            .find(|finding| matches!(finding.rule, Rule::OpaqueSourceScope))
            .ok_or_else(|| anyhow!("expected strongest-effect mismatch"))?;
        assert!(finding.detail.contains("contract `demo.safe` GET /demo"));
        assert!(finding.detail.contains("crates/demo/src/lib.rs:"));
        assert!(finding.detail.contains("crates/demo/src/ports.rs:"));
        Ok(())
    }

    #[test]
    fn generated_non_localonly_marker_is_rejected() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let generated = workspace.0.join("generated/src/http/demo_v1.rs");
        workspace.replace(&generated, "http::LocalOnly", "http::LocalTx")?;
        assert!(!check_root(&workspace.0)?.1.is_empty());
        Ok(())
    }

    #[test]
    fn dead_helper_cannot_supply_evidence_and_endpoint_wrapper_is_opaque() -> Result<()> {
        let dead = WorkspaceFixture::new()?;
        dead.replace(
            &dead.source(),
            "struct Demo;",
            r#"fn dead_helper(state: ReadState) {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::safe::ROUTE,
        handler,
    ).unwrap().with_classified_state(state);
}
struct Demo;"#,
        )?;
        assert!(
            check_root(&dead.0)?.1.is_empty(),
            "dead helper polluted mount evidence"
        );

        let wrapper = WorkspaceFixture::new()?;
        wrapper.replace(
            &wrapper.source(),
            "struct Demo;",
            "fn identity(value: ::httpserve::GeneratedPrimaryEndpoint) -> ::httpserve::GeneratedPrimaryEndpoint { value }\nstruct Demo;",
        )?;
        wrapper.replace(
            &wrapper.source(),
            "Ok(router.mount(",
            "Ok(router.mount(identity(",
        )?;
        wrapper.replace(&wrapper.source(), "            )?)", "            ))?)")?;
        assert!(
            !check_root(&wrapper.0)?.1.is_empty(),
            "opaque endpoint wrapper passed"
        );
        Ok(())
    }

    #[test]
    fn every_forbidden_effect_and_cross_tenant_privilege_is_red() -> Result<()> {
        for effect in ["WriteEffect", "OutboxEffect", "WorkflowEffect"] {
            let workspace = WorkspaceFixture::new()?;
            workspace.replace(&workspace.ports(), "ReadEffect);", &format!("{effect});"))?;
            assert!(
                !check_root(&workspace.0)?.1.is_empty(),
                "{effect} unexpectedly passed"
            );
        }
        let workspace = WorkspaceFixture::new()?;
        workspace.replace(
            &workspace.source(),
            "type Privilege = ::diport::LocalPrivilege;",
            "type Privilege = ::diport::CrossTenantPrivilege;",
        )?;
        assert!(
            !check_root(&workspace.0)?.1.is_empty(),
            "cross-tenant unexpectedly passed"
        );
        Ok(())
    }
}
