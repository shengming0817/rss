//! Static producer-side L2 closure projected from the same generated route markers compiled by
//! serving, domain service/UoW ports, and the Postgres implementations.
//!
//! INVARIANT: L2-PRODUCER-RECEIPT-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::broken_producer_chain_is_rejected", anti_vacuity = "l2_assurance::tests::workspace_inventory_is_exact_and_deterministic" }——
//! every active HTTP OutboxFact contract has one canonical production mount whose handler starts
//! with `ProducerMarker<RouteMarker>`, at least one domain service and one domain UoW trait carrying
//! the matching `ProducerAssuranceReceipt<RouteMarker>`, and a Postgres implementation that
//! consumes that receipt into an exact fact authorization. The route/fact binding itself is Hard;
//! this cross-file exact-set join is the smallest non-vacuous Medium carrier.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::repository_contract::DiscoveredContract;
use syn::parse::ParseStream;
use syn::visit::{self, Visit};
use syn::{Attribute, FnArg, GenericArgument, Item, PathArguments, Token, Type};

use crate::localtx_coverage::{ServingEvidenceSource, canonical_serving_evidence};

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RustItemProjection {
    pub(crate) repo_path: String,
    pub(crate) symbol: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ProducerClosureProjection {
    pub(crate) handler: RustItemProjection,
    pub(crate) effects: Vec<RustItemProjection>,
}

/// Collect the exact producer-side receipt closure for the already validated active L2 universe.
pub(crate) fn collect(
    root: &Path,
    producers: &BTreeMap<String, &DiscoveredContract>,
) -> Result<BTreeMap<String, ProducerClosureProjection>> {
    let mut by_domain = BTreeMap::<String, Vec<(&String, &DiscoveredContract)>>::new();
    for (id, contract) in producers {
        by_domain
            .entry(contract.manifest.domain.clone())
            .or_default()
            .push((id, *contract));
    }

    let mut closures = BTreeMap::new();
    for (domain, contracts) in by_domain {
        let serving = canonical_serving_evidence(root, ServingEvidenceSource::Domain(&domain))?;
        let domain_files =
            production_rs_files(root, &root.join("crates").join(&domain).join("src"))?;
        let postgres_files = production_rs_files(root, &root.join("adapters/postgres/src"))?;
        let aliases = receipt_aliases(&domain_files)?;
        let fact_aliases = fact_contract_aliases(root, &domain_files)?;
        let expected_fact_aliases = expected_fact_aliases(&contracts, &fact_aliases)?;
        let domain_evidence = collect_domain_receipts(&domain_files, &aliases)?;
        let postgres_evidence = collect_postgres_receipts(
            &postgres_files,
            &domain_evidence.traits,
            &aliases,
            &expected_fact_aliases,
        )?;

        for (id, contract) in contracts {
            let generated = crate::codegen::GeneratedCarrier::from_contract(contract)?;
            let key = generated.route_key()?;
            let mounts = serving
                .mounts
                .get(key)
                .with_context(|| format!("producer {id} has no canonical production mount"))?;
            ensure!(
                mounts.len() == 1,
                "producer {id} must have exactly one canonical mount, got {mounts:?}"
            );
            let mount = mounts.first().context("canonical mount set is empty")?;
            let handler = mounted_producer_handler(root, &mount.source, key)?;
            let owner = domain_evidence
                .carriers
                .get(key)
                .with_context(|| format!("producer {id} lacks domain receipt carriers"))?;
            ensure!(
                domain_evidence.traits.contains_key(key),
                "producer {id} receipt never reaches a domain UoW trait"
            );
            let postgres = postgres_evidence
                .get(key)
                .with_context(|| format!("producer {id} receipt never reaches Postgres"))?;
            let mut effects = owner.union(postgres).cloned().collect::<Vec<_>>();
            effects.sort();
            ensure!(
                !effects.is_empty(),
                "producer {id} has empty effect closure"
            );
            ensure!(
                closures
                    .insert(id.clone(), ProducerClosureProjection { handler, effects },)
                    .is_none(),
                "duplicate producer closure: {id}"
            );
        }
    }
    ensure_exact_ids(producers.keys(), closures.keys())?;
    Ok(closures)
}

#[derive(Debug, Default)]
struct DomainEvidence {
    carriers: BTreeMap<String, BTreeSet<RustItemProjection>>,
    traits: BTreeMap<String, BTreeSet<TraitMethod>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TraitMethod {
    trait_name: String,
    method_name: String,
}

fn collect_domain_receipts(
    files: &[SourceFile],
    aliases: &BTreeMap<String, String>,
) -> Result<DomainEvidence> {
    let mut evidence = DomainEvidence::default();
    for file in files {
        collect_items(&file.syntax.items, true, &mut |item, production| {
            if !production {
                return Ok(());
            }
            match item {
                Item::Trait(item) => {
                    let trait_names = trait_names(item)?;
                    for method in &item.items {
                        let syn::TraitItem::Fn(method) = method else {
                            continue;
                        };
                        for key in receipt_keys_in_signature(&method.sig, aliases) {
                            evidence.carriers.entry(key.clone()).or_default().insert(
                                RustItemProjection {
                                    repo_path: file.repo_path.clone(),
                                    symbol: item.ident.to_string(),
                                },
                            );
                            for trait_name in &trait_names {
                                evidence.traits.entry(key.clone()).or_default().insert(
                                    TraitMethod {
                                        trait_name: trait_name.clone(),
                                        method_name: method.sig.ident.to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
                Item::Impl(item) => {
                    if file.repo_path.contains("/internal/") {
                        return Ok(());
                    }
                    let Some(symbol) = type_last_ident(&item.self_ty) else {
                        return Ok(());
                    };
                    for method in &item.items {
                        let syn::ImplItem::Fn(method) = method else {
                            continue;
                        };
                        for (key, binding) in receipt_bindings_in_signature(&method.sig, aliases) {
                            ensure!(
                                binding_is_forwarded(&method.block, &binding),
                                "{}::{symbol}::{} drops producer receipt `{binding}` instead of forwarding it as a call argument",
                                file.repo_path,
                                method.sig.ident
                            );
                            evidence
                                .carriers
                                .entry(key)
                                .or_default()
                                .insert(RustItemProjection {
                                    repo_path: file.repo_path.clone(),
                                    symbol: symbol.clone(),
                                });
                        }
                    }
                }
                Item::Fn(item) => {
                    if file.repo_path.contains("/internal/") {
                        return Ok(());
                    }
                    for (key, binding) in receipt_bindings_in_signature(&item.sig, aliases) {
                        ensure!(
                            binding_is_forwarded(&item.block, &binding),
                            "{}::{} drops producer receipt `{binding}` instead of forwarding it as a call argument",
                            file.repo_path,
                            item.sig.ident
                        );
                        evidence
                            .carriers
                            .entry(key)
                            .or_default()
                            .insert(RustItemProjection {
                                repo_path: file.repo_path.clone(),
                                symbol: item.sig.ident.to_string(),
                            });
                    }
                }
                _ => {}
            }
            Ok(())
        })?;
    }
    Ok(evidence)
}

fn trait_names(item: &syn::ItemTrait) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::from([item.ident.to_string()]);
    for attribute in &item.attrs {
        let segments = attribute
            .path()
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if segments.as_slice() != ["trait_variant", "make"] {
            continue;
        }
        let generated = attribute.parse_args_with(|input: ParseStream<'_>| {
            let ident: syn::Ident = input.parse()?;
            input.parse::<Token![:]>()?;
            let _: proc_macro2::TokenStream = input.parse()?;
            Ok(ident)
        })?;
        names.insert(generated.to_string());
    }
    Ok(names)
}

fn collect_postgres_receipts(
    files: &[SourceFile],
    traits: &BTreeMap<String, BTreeSet<TraitMethod>>,
    receipt_aliases: &BTreeMap<String, String>,
    expected_fact_aliases: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, BTreeSet<RustItemProjection>>> {
    let mut by_trait_method = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for (key, methods) in traits {
        for method in methods {
            by_trait_method
                .entry((method.trait_name.clone(), method.method_name.clone()))
                .or_default()
                .insert(key.clone());
        }
    }
    let mut evidence = BTreeMap::<String, BTreeSet<RustItemProjection>>::new();
    for file in files {
        collect_items(&file.syntax.items, true, &mut |item, production| {
            if !production {
                return Ok(());
            }
            let Item::Impl(item) = item else {
                return Ok(());
            };
            let Some((_, trait_path, _)) = &item.trait_ else {
                return Ok(());
            };
            let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string()) else {
                return Ok(());
            };
            let Some(symbol) = type_last_ident(&item.self_ty) else {
                return Ok(());
            };
            for method in &item.items {
                let syn::ImplItem::Fn(method) = method else {
                    continue;
                };
                let Some(keys) =
                    by_trait_method.get(&(trait_name.clone(), method.sig.ident.to_string()))
                else {
                    continue;
                };
                for key in keys {
                    let bindings = receipt_bindings_in_signature(&method.sig, receipt_aliases)
                        .into_iter()
                        .filter_map(|(binding_key, binding)| {
                            (binding_key == *key).then_some(binding)
                        })
                        .collect::<Vec<_>>();
                    ensure!(
                        bindings.len() == 1,
                        "{}::{symbol}::{} must bind exactly one receipt for {key}, got {bindings:?}",
                        file.repo_path,
                        method.sig.ident
                    );
                    let fact_alias = expected_fact_aliases.get(key).with_context(|| {
                        format!("producer route {key} has no emitted-fact alias")
                    })?;
                    ensure!(
                        method_authorizes_expected_fact(&method.block, &bindings[0], fact_alias,),
                        "{}::{symbol}::{} must close `{}` via `{}.authorize({fact_alias})` and authorization.fact_contract()",
                        file.repo_path,
                        method.sig.ident,
                        key,
                        bindings[0],
                    );
                    evidence
                        .entry(key.clone())
                        .or_default()
                        .insert(RustItemProjection {
                            repo_path: file.repo_path.clone(),
                            symbol: symbol.clone(),
                        });
                }
            }
            Ok(())
        })?;
    }
    Ok(evidence)
}

fn mounted_producer_handler(root: &Path, source: &str, key: &str) -> Result<RustItemProjection> {
    let file = SourceFile::read(root, &root.join(source))?;
    let mut matches = Vec::new();
    collect_items(&file.syntax.items, true, &mut |item, production| {
        if production
            && let Item::Fn(function) = item
            && let Some(marker_binding) = function.sig.inputs.iter().find_map(|argument| {
                let FnArg::Typed(argument) = argument else {
                    return None;
                };
                let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                    return None;
                };
                (marker_route_key(&argument.ty, "ProducerMarker").as_deref() == Some(key))
                    .then(|| binding.ident.to_string())
            })
            && marker_into_receipt(&function.block, &marker_binding)
        {
            matches.push(RustItemProjection {
                repo_path: file.repo_path.clone(),
                symbol: function.sig.ident.to_string(),
            });
        }
        Ok(())
    })?;
    ensure!(
        matches.len() == 1,
        "mounted producer {key} must have exactly one ProducerMarker handler that consumes its named marker with `into_receipt()` in {source}, got {matches:?}"
    );
    matches.pop().context("producer handler disappeared")
}

fn receipt_aliases(files: &[SourceFile]) -> Result<BTreeMap<String, String>> {
    let mut aliases = BTreeMap::new();
    for file in files {
        collect_items(&file.syntax.items, true, &mut |item, production| {
            if production
                && let Item::Type(alias) = item
                && let Some(key) = receipt_route_key(&alias.ty, &BTreeMap::new())
            {
                let name = alias.ident.to_string();
                match aliases.insert(name.clone(), key.clone()) {
                    Some(old) if old != key => {
                        bail!("producer receipt alias `{name}` maps to both {old} and {key}")
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
    }
    Ok(aliases)
}

fn fact_contract_aliases(root: &Path, files: &[SourceFile]) -> Result<BTreeMap<String, String>> {
    let mut aliases = BTreeMap::new();
    for file in files {
        collect_items(&file.syntax.items, true, &mut |item, production| {
            if !production {
                return Ok(());
            }
            let Item::Use(item) = item else {
                return Ok(());
            };
            for (module_path, alias) in generated_fact_exports(item) {
                let fact_id = generated_fact_contract_id(root, &module_path)?;
                match aliases.insert(fact_id.clone(), alias.clone()) {
                    Some(old) if old != alias => {
                        bail!(
                            "generated fact `{fact_id}` is exported as both `{old}` and `{alias}`"
                        )
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
    }
    Ok(aliases)
}

fn generated_fact_exports(item: &syn::ItemUse) -> Vec<(Vec<String>, String)> {
    if !matches!(item.vis, syn::Visibility::Public(_)) {
        return Vec::new();
    }
    fn collect(
        tree: &syn::UseTree,
        prefix: &mut Vec<String>,
        exports: &mut Vec<(Vec<String>, String)>,
    ) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, exports);
                prefix.pop();
            }
            syn::UseTree::Rename(rename)
                if rename.ident == "CONTRACT"
                    && prefix.first().is_some_and(|segment| segment == "generated")
                    && prefix.get(1).is_some_and(|segment| segment == "event")
                    && prefix.len() >= 3 =>
            {
                exports.push((prefix[2..].to_vec(), rename.rename.to_string()));
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    collect(tree, prefix, exports);
                }
            }
            _ => {}
        }
    }

    let mut exports = Vec::new();
    collect(&item.tree, &mut Vec::new(), &mut exports);
    exports
}

fn generated_fact_contract_id(root: &Path, module_path: &[String]) -> Result<String> {
    let (file_module, nested_modules) = module_path
        .split_first()
        .context("generated fact export has no module")?;
    let path = root
        .join("generated/src/event")
        .join(format!("{file_module}.rs"));
    let file = SourceFile::read(root, &path)?;
    let mut items = file.syntax.items.as_slice();
    for module_name in nested_modules {
        let module = items.iter().find_map(|item| match item {
            Item::Mod(module) if module.ident == module_name => Some(module),
            _ => None,
        });
        let (_, nested) = module
            .and_then(|module| module.content.as_ref())
            .with_context(|| {
                format!(
                    "generated fact module `{}` is absent from {}",
                    module_path.join("::"),
                    file.repo_path
                )
            })?;
        items = nested;
    }
    items
        .iter()
        .find_map(|item| match item {
            Item::Const(item) if item.ident == "CONTRACT_ID" => match item.expr.as_ref() {
                syn::Expr::Lit(literal) => match &literal.lit {
                    syn::Lit::Str(value) => Some(value.value()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        })
        .with_context(|| {
            format!(
                "generated fact module `{}` has no string CONTRACT_ID",
                module_path.join("::")
            )
        })
}

fn expected_fact_aliases(
    producers: &[(&String, &DiscoveredContract)],
    fact_aliases: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut expected = BTreeMap::new();
    for (producer_id, contract) in producers {
        let outbox = contract
            .manifest
            .capabilities
            .outbox
            .as_ref()
            .with_context(|| format!("producer {producer_id} has no outbox capability"))?;
        ensure!(
            outbox.emits.len() == 1,
            "producer {producer_id} must emit exactly one fact, got {:?}",
            outbox.emits
        );
        let fact_id = &outbox.emits[0];
        let alias = fact_aliases.get(fact_id).with_context(|| {
            format!("producer {producer_id} emits `{fact_id}` without a domain `pub use generated::event::...::CONTRACT as ALIAS`")
        })?;
        let generated = crate::codegen::GeneratedCarrier::from_contract(contract)?;
        let key = generated.route_key()?;
        ensure!(
            expected.insert(key.to_string(), alias.clone()).is_none(),
            "duplicate producer route key {key}"
        );
    }
    Ok(expected)
}

fn receipt_keys_in_signature(
    signature: &syn::Signature,
    aliases: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(fn_arg_type)
        .filter_map(|ty| receipt_route_key(ty, aliases))
        .collect()
}

fn receipt_bindings_in_signature(
    signature: &syn::Signature,
    aliases: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    signature
        .inputs
        .iter()
        .filter_map(|arg| {
            let FnArg::Typed(arg) = arg else { return None };
            let syn::Pat::Ident(binding) = arg.pat.as_ref() else {
                return None;
            };
            receipt_route_key(&arg.ty, aliases).map(|key| (key, binding.ident.to_string()))
        })
        .collect()
}

fn receipt_route_key(ty: &Type, aliases: &BTreeMap<String, String>) -> Option<String> {
    if let Type::Path(path) = ty {
        let last = path.path.segments.last()?;
        if last.ident == "ProducerAssuranceReceipt" {
            let PathArguments::AngleBracketed(arguments) = &last.arguments else {
                return None;
            };
            return arguments.args.iter().find_map(|argument| match argument {
                GenericArgument::Type(ty) => route_marker_key(ty),
                _ => None,
            });
        }
        if let Some(key) = aliases.get(&last.ident.to_string()) {
            return Some(key.clone());
        }
    }
    None
}

fn marker_route_key(ty: &Type, marker: &str) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    let last = path.path.segments.last()?;
    if last.ident != marker {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        GenericArgument::Type(ty) => route_marker_key(ty),
        _ => None,
    })
}

fn route_marker_key(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    let segments = path
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>();
    let http = segments.iter().position(|segment| segment == "http")?;
    (segments.first().is_some_and(|s| s == "generated")
        && segments.last().is_some_and(|s| s == "RouteMarker")
        && http + 2 < segments.len())
    .then(|| segments[http + 1..segments.len() - 1].join("::"))
}

fn fn_arg_type(argument: &FnArg) -> Option<&Type> {
    match argument {
        FnArg::Typed(argument) => Some(&argument.ty),
        FnArg::Receiver(_) => None,
    }
}

fn type_last_ident(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn binding_is_forwarded(block: &syn::Block, binding: &str) -> bool {
    struct BindingForward<'a> {
        binding: &'a str,
        forwarded: bool,
    }
    impl Visit<'_> for BindingForward<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if call
                .args
                .iter()
                .any(|argument| expr_is_ident(argument, self.binding))
            {
                self.forwarded = true;
            }
            visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call
                .args
                .iter()
                .any(|argument| expr_is_ident(argument, self.binding))
            {
                self.forwarded = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = BindingForward {
        binding,
        forwarded: false,
    };
    visitor.visit_block(block);
    visitor.forwarded
}

fn marker_into_receipt(block: &syn::Block, binding: &str) -> bool {
    struct IntoReceipt<'a> {
        binding: &'a str,
        found: bool,
    }
    impl Visit<'_> for IntoReceipt<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == "into_receipt"
                && call.args.is_empty()
                && expr_is_ident(&call.receiver, self.binding)
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = IntoReceipt {
        binding,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

fn method_authorizes_expected_fact(
    block: &syn::Block,
    receipt_binding: &str,
    fact_alias: &str,
) -> bool {
    fn block_closes(block: &syn::Block, receipt_binding: &str, fact_alias: &str) -> bool {
        block.stmts.iter().enumerate().any(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            let syn::Pat::Ident(authorization) = &local.pat else {
                return false;
            };
            let Some(initializer) = &local.init else {
                return false;
            };
            expr_contains_authorize(&initializer.expr, receipt_binding, fact_alias)
                && block.stmts[index + 1..].iter().any(|statement| {
                    statement_closes_authorization(statement, &authorization.ident.to_string())
                })
        })
    }

    struct NestedClosure<'a> {
        receipt_binding: &'a str,
        fact_alias: &'a str,
        found: bool,
    }
    impl Visit<'_> for NestedClosure<'_> {
        fn visit_block(&mut self, block: &syn::Block) {
            if block_closes(block, self.receipt_binding, self.fact_alias) {
                self.found = true;
                return;
            }
            visit::visit_block(self, block);
        }
    }

    let mut visitor = NestedClosure {
        receipt_binding,
        fact_alias,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

fn expr_contains_authorize(expr: &syn::Expr, receipt_binding: &str, fact_alias: &str) -> bool {
    struct ExpectedAuthorize<'a> {
        receipt_binding: &'a str,
        fact_alias: &'a str,
        found: bool,
    }
    impl Visit<'_> for ExpectedAuthorize<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == "authorize"
                && expr_is_ident(&call.receiver, self.receipt_binding)
                && call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|argument| expr_is_ident(argument, self.fact_alias))
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = ExpectedAuthorize {
        receipt_binding,
        fact_alias,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn statement_closes_authorization(statement: &syn::Stmt, authorization_binding: &str) -> bool {
    struct AuthorizationClosure<'a> {
        authorization_binding: &'a str,
        found: bool,
    }
    impl Visit<'_> for AuthorizationClosure<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            let fact_contract_argument = call
                .args
                .iter()
                .any(|argument| expr_contains_fact_contract(argument, self.authorization_binding));
            if (call.method == "matches_contract" && fact_contract_argument)
                || (call.method == "commit_authorized"
                    && expr_is_ident(&call.receiver, "self")
                    && fact_contract_argument)
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = AuthorizationClosure {
        authorization_binding,
        found: false,
    };
    visitor.visit_stmt(statement);
    visitor.found
}

fn expr_contains_fact_contract(expr: &syn::Expr, authorization_binding: &str) -> bool {
    struct FactContract<'a> {
        authorization_binding: &'a str,
        found: bool,
    }
    impl Visit<'_> for FactContract<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == "fact_contract"
                && call.args.is_empty()
                && expr_is_ident(&call.receiver, self.authorization_binding)
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = FactContract {
        authorization_binding,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn expr_is_ident(expr: &syn::Expr, expected: &str) -> bool {
    matches!(expr, syn::Expr::Path(path) if path.path.is_ident(expected))
}

fn collect_items(
    items: &[Item],
    production: bool,
    visit_item: &mut impl FnMut(&Item, bool) -> Result<()>,
) -> Result<()> {
    for item in items {
        let production = production && attrs_are_production(item_attrs(item));
        visit_item(item, production)?;
        if let Item::Mod(module) = item
            && let Some((_, nested)) = &module.content
        {
            collect_items(nested, production, visit_item)?;
        }
    }
    Ok(())
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn attrs_are_production(attrs: &[Attribute]) -> bool {
    !attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            || attribute.path().is_ident("cfg_attr")
            || attribute.path().is_ident("test")
    })
}

struct SourceFile {
    repo_path: String,
    syntax: syn::File,
}

impl SourceFile {
    fn read(root: &Path, path: &Path) -> Result<Self> {
        Self::read_with_hook(root, path, || {})
    }

    fn read_with_hook(root: &Path, path: &Path, after_open: impl FnOnce()) -> Result<Self> {
        let repo_path = path
            .strip_prefix(root)
            .with_context(|| format!("producer source escaped repository: {}", path.display()))?
            .to_str()
            .context("producer source path is not UTF-8")?
            .replace('\\', "/");
        ensure!(
            !Path::new(&repo_path)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir)),
            "producer source escaped repository: {}",
            path.display()
        );
        let source = crate::generated_file::read_stable_utf8_file_with_hook(
            path,
            MAX_SOURCE_BYTES,
            "producer source",
            after_open,
        )?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parse producer source {}", path.display()))?;
        Ok(Self { repo_path, syntax })
    }
}

fn production_rs_files(root: &Path, directory: &Path) -> Result<Vec<SourceFile>> {
    let mut paths = Vec::new();
    collect_rs_paths(directory, &mut paths)?;
    paths.sort();
    paths
        .into_iter()
        .filter(|path| {
            !path.components().any(|component| {
                component.as_os_str().to_str().is_some_and(|segment| {
                    matches!(segment, "tests" | "test_support" | "integration_tests.rs")
                })
            })
        })
        .map(|path| SourceFile::read(root, &path))
        .collect()
}

fn collect_rs_paths(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("read producer source directory {}", directory.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "producer source directory is not real: {}",
        directory.display()
    );
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read producer source directory {}", directory.display()))?
    {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "producer source tree contains symlink: {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_rs_paths(&path, paths)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn ensure_exact_ids<'a>(
    expected: impl Iterator<Item = &'a String>,
    actual: impl Iterator<Item = &'a String>,
) -> Result<()> {
    let expected = expected.cloned().collect::<BTreeSet<_>>();
    let actual = actual.cloned().collect::<BTreeSet<_>>();
    ensure!(
        expected == actual,
        "producer receipt exact-set drift: missing={:?} extra={:?}",
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(&expected).collect::<Vec<_>>()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_producer_chain_is_rejected() -> anyhow::Result<()> {
        let source = syn::parse_file(
            r#"
            type PublishReceipt = httpserve::ProducerAssuranceReceipt<
                generated::http::settings_v1::RouteMarker
            >;
            struct Service;
            impl Service {
                fn publish(receipt: PublishReceipt) { let _ = 1; }
            }
        "#,
        )?;
        let file = SourceFile {
            repo_path: "crates/settings/src/application.rs".into(),
            syntax: source,
        };
        let aliases = receipt_aliases(std::slice::from_ref(&file))?;
        let error = match collect_domain_receipts(&[file], &aliases) {
            Ok(_) => anyhow::bail!("dropped receipt unexpectedly closed producer chain"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("drops producer receipt"));
        Ok(())
    }

    #[test]
    fn domain_receipt_receiver_use_is_not_downward_forwarding() -> anyhow::Result<()> {
        let source = syn::parse_file(
            r#"
            type PublishReceipt = httpserve::ProducerAssuranceReceipt<
                generated::http::settings_v1::RouteMarker
            >;
            struct Service;
            impl Service {
                fn publish(receipt: PublishReceipt) { receipt.inspect(); }
            }
        "#,
        )?;
        let file = SourceFile {
            repo_path: "crates/settings/src/application.rs".into(),
            syntax: source,
        };
        let aliases = receipt_aliases(std::slice::from_ref(&file))?;
        assert!(collect_domain_receipts(&[file], &aliases).is_err());
        Ok(())
    }

    #[test]
    fn mounted_marker_noop_is_rejected() -> anyhow::Result<()> {
        let fixture = TempRoot::new("marker-noop")?;
        let source = fixture.path.join("crates/settings/src/application.rs");
        fs::create_dir_all(source.parent().context("source parent")?)?;
        fs::write(
            &source,
            r#"
            async fn handler(
                marker: httpserve::ProducerMarker<generated::http::settings_v1::RouteMarker>,
            ) { let _ = marker; }
            "#,
        )?;
        assert!(
            mounted_producer_handler(
                &fixture.path,
                "crates/settings/src/application.rs",
                "settings_v1",
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn route_marker_and_receipt_alias_share_one_key() -> anyhow::Result<()> {
        let marker: Type = syn::parse_str(
            "httpserve::ProducerMarker<generated::http::identity_v1::login::RouteMarker>",
        )?;
        let receipt: Type = syn::parse_str(
            "httpserve::ProducerAssuranceReceipt<generated::http::identity_v1::login::RouteMarker>",
        )?;
        assert_eq!(
            marker_route_key(&marker, "ProducerMarker").as_deref(),
            Some("identity_v1::login")
        );
        assert_eq!(
            receipt_route_key(&receipt, &BTreeMap::new()).as_deref(),
            Some("identity_v1::login")
        );
        Ok(())
    }

    #[test]
    fn generated_trait_variant_reaches_postgres_impl() -> anyhow::Result<()> {
        let domain = syn::parse_file(
            r#"
            type PublishReceipt = httpserve::ProducerAssuranceReceipt<
                generated::http::settings_v1::RouteMarker
            >;
            #[trait_variant::make(ConfigWriteRepo: Send)]
            trait ConfigWriteRepoLocal {
                async fn commit(&self, receipt: PublishReceipt);
            }
            "#,
        )?;
        let postgres = syn::parse_file(
            r#"
            impl ConfigWriteRepo for PgConfigRepo {
                async fn commit(&self, receipt: PublishReceipt) {
                    let authorization = receipt.authorize(CONFIG_VERSION_CHANGED_CONTRACT).unwrap();
                    if !env.matches_contract(authorization.fact_contract()) { return; }
                }
            }
            "#,
        )?;
        let domain_file = SourceFile {
            repo_path: "crates/settings/src/ports.rs".into(),
            syntax: domain,
        };
        let postgres_file = SourceFile {
            repo_path: "adapters/postgres/src/config_repo.rs".into(),
            syntax: postgres,
        };
        let aliases = receipt_aliases(std::slice::from_ref(&domain_file))?;
        let domain = collect_domain_receipts(&[domain_file], &aliases)?;
        let evidence = collect_postgres_receipts(
            &[postgres_file],
            &domain.traits,
            &aliases,
            &BTreeMap::from([(
                "settings_v1".into(),
                "CONFIG_VERSION_CHANGED_CONTRACT".into(),
            )]),
        )?;
        assert!(evidence.contains_key("settings_v1"));
        Ok(())
    }

    #[test]
    fn postgres_unrelated_receiver_wrong_fact_and_drop_are_rejected() -> anyhow::Result<()> {
        let valid: syn::Block = syn::parse_str(
            r#"{
                let authorization = receipt.authorize(EXACT_FACT).unwrap();
                if !env.matches_contract(authorization.fact_contract()) { return; }
            }"#,
        )?;
        assert!(method_authorizes_expected_fact(
            &valid,
            "receipt",
            "EXACT_FACT"
        ));

        for invalid in [
            r#"{
                let authorization = unrelated.authorize(EXACT_FACT).unwrap();
                if !env.matches_contract(authorization.fact_contract()) { return; }
            }"#,
            r#"{
                let authorization = receipt.authorize(WRONG_FACT).unwrap();
                if !env.matches_contract(authorization.fact_contract()) { return; }
            }"#,
            r#"{
                let _authorization = receipt.authorize(EXACT_FACT).unwrap();
            }"#,
            r#"{
                let authorization = receipt.authorize(EXACT_FACT).unwrap();
                if !env.matches_contract(OTHER_FACT) { return; }
                drop(authorization.fact_contract());
            }"#,
        ] {
            let block: syn::Block = syn::parse_str(invalid)?;
            assert!(
                !method_authorizes_expected_fact(&block, "receipt", "EXACT_FACT"),
                "invalid producer authorization closure was accepted: {invalid}"
            );
        }
        Ok(())
    }

    #[test]
    fn postgres_commit_authorized_closes_exact_fact_contract() -> anyhow::Result<()> {
        let block: syn::Block = syn::parse_str(
            r#"{
                let authorization = receipt.authorize(EXACT_FACT).unwrap();
                self.commit_authorized(
                    move || authorization.fact_contract(),
                    mutation,
                ).await;
            }"#,
        )?;
        assert!(method_authorizes_expected_fact(
            &block,
            "receipt",
            "EXACT_FACT"
        ));
        Ok(())
    }

    #[test]
    fn emitted_fact_alias_is_derived_from_generated_export() -> anyhow::Result<()> {
        let fixture = TempRoot::new("fact-alias")?;
        let generated = fixture.path.join("generated/src/event/settings_v1.rs");
        fs::create_dir_all(generated.parent().context("generated parent")?)?;
        fs::write(
            &generated,
            r#"pub const CONTRACT_ID: &str = "settings.config-version-changed";"#,
        )?;
        let domain = syn::parse_file(
            r#"
            pub use generated::event::settings_v1::CONTRACT as CONFIG_VERSION_CHANGED_CONTRACT;
            "#,
        )?;
        let aliases = fact_contract_aliases(
            &fixture.path,
            &[SourceFile {
                repo_path: "crates/settings/src/ports.rs".into(),
                syntax: domain,
            }],
        )?;
        assert_eq!(
            aliases
                .get("settings.config-version-changed")
                .map(String::as_str),
            Some("CONFIG_VERSION_CHANGED_CONTRACT")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_symlink_replacement_after_open_is_rejected() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = TempRoot::new("source-symlink-replacement")?;
        let source = fixture.path.join("source.rs");
        let outside = fixture.path.join("outside.rs");
        fs::write(&source, "fn original() {}\n")?;
        fs::write(&outside, "fn outside() {}\n")?;
        let opened = fixture.path.join("opened.rs");
        let result = SourceFile::read_with_hook(&fixture.path, &source, || {
            assert!(fs::rename(&source, &opened).is_ok());
            assert!(symlink(&outside, &source).is_ok());
        });
        let error = result
            .err()
            .context("source symlink replacement was accepted")?;
        assert!(
            error.to_string().contains("replaced during read"),
            "{error:#}"
        );
        Ok(())
    }

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(name: &str) -> anyhow::Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "rss-producer-assurance-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            if root.exists() {
                fs::remove_dir_all(&root)?;
            }
            fs::create_dir_all(&root)?;
            Ok(Self { path: root })
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
