//! Static producer-side L2 execution graph projected from the same generated route markers,
//! production composition, typed domain ports and Postgres transaction funnel compiled by serving.
//!
//! INVARIANT: L2-PRODUCER-EXECUTION-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::postgres_provider_without_producer_tx_is_rejected", anti_vacuity = "l2_assurance::tests::workspace_inventory_is_exact_and_deterministic" }——
//! every active HTTP OutboxFact contract resolves from its exact mounted handler through live
//! receipt call edges to one typed domain port, its injected Postgres provider, `producer_tx`,
//! `TxCapability`, canonical append and settlement. Ambiguous, macro-hidden, dead, test-only or
//! missing edges fail closed, and terminal facts equal manifest `emits`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::repository_contract::DiscoveredContract;
use syn::parse::ParseStream;
use syn::visit::{self, Visit};
use syn::{Attribute, FnArg, GenericArgument, Item, PathArguments, Token, Type};

use crate::localtx_coverage::{ServingEvidenceSource, canonical_serving_evidence};
use crate::production_composition::{
    ProducerCompositionPort, ProductionCompositionProjection, collect_producer_composition,
};

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RustItemProjection {
    pub(crate) repo_path: String,
    pub(crate) symbol: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ProducerExecutionProjection {
    pub(crate) route: RustItemProjection,
    pub(crate) mounted_handler: RustItemProjection,
    pub(crate) terminals: Vec<ProducerTerminalProjection>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProducerTerminalProjection {
    pub(crate) fact_id: String,
    pub(crate) domain_path: Vec<RustItemProjection>,
    pub(crate) port_method: RustItemProjection,
    pub(crate) provider_method: RustItemProjection,
    pub(crate) production_composition: ProductionCompositionProjection,
    pub(crate) transaction: RustItemProjection,
    pub(crate) capability: RustItemProjection,
    pub(crate) append: RustItemProjection,
    pub(crate) settlement: RustItemProjection,
    pub(crate) rollback: RustItemProjection,
    pub(crate) commit_unknown: RustItemProjection,
    pub(crate) rollback_failed: RustItemProjection,
    pub(crate) no_replay: RustItemProjection,
}

/// Collect the exact producer-side receipt closure for the already validated active L2 universe.
pub(crate) fn collect(
    root: &Path,
    producers: &BTreeMap<String, &DiscoveredContract>,
) -> Result<BTreeMap<String, ProducerExecutionProjection>> {
    let compositions = collect_producer_composition(root)?;
    let transaction_closure = canonical_transaction_closure(root)?;
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
        let postgres_evidence = collect_postgres_terminals(
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
            let mounted_handler = exact_mounted_producer_handler(
                root,
                &mount.source,
                &mount.handler,
                key,
                &domain_evidence,
            )?;
            let (domain_path, port) =
                reachable_domain_path(root, &mount.source, &mount.handler, key, &domain_evidence)?;
            let provider_terminals = postgres_evidence
                .get(key)
                .with_context(|| format!("producer {id} receipt never reaches Postgres"))?;
            let expected_facts = contract
                .manifest
                .capabilities
                .outbox
                .as_ref()
                .context("validated producer missing outbox capability")?
                .emits
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let actual_facts = provider_terminals
                .iter()
                .map(|terminal| terminal.fact_id.clone())
                .collect::<BTreeSet<_>>();
            ensure!(
                expected_facts == actual_facts,
                "producer {id} terminal fact set mismatch: expected={expected_facts:?} actual={actual_facts:?}"
            );
            let composition_port = composition_port(&port)?;
            let production_composition = compositions
                .get(&composition_port)
                .with_context(|| {
                    format!(
                        "producer {id} lacks production composition for {}",
                        port.trait_name
                    )
                })?
                .clone();
            let mut terminals = provider_terminals
                .iter()
                .map(|provider| {
                    ensure!(
                        provider.port_method == port,
                        "producer {id} execution reaches {}::{} but Postgres terminal resolves {}::{}",
                        port.trait_name,
                        port.method_name,
                        provider.port_method.trait_name,
                        provider.port_method.method_name
                    );
                    Ok(ProducerTerminalProjection {
                        fact_id: provider.fact_id.clone(),
                        domain_path: domain_path.clone(),
                        port_method: port.projection.clone(),
                        provider_method: provider.provider_method.clone(),
                        production_composition: production_composition.clone(),
                        transaction: provider.transaction.clone(),
                        capability: transaction_closure.capability.clone(),
                        append: transaction_closure.append.clone(),
                        settlement: transaction_closure.settlement.clone(),
                        rollback: transaction_closure.rollback.clone(),
                        commit_unknown: transaction_closure.commit_unknown.clone(),
                        rollback_failed: transaction_closure.rollback_failed.clone(),
                        no_replay: provider.no_replay.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            terminals.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
            let route = generated.item(crate::codegen::GeneratedItem::Spec)?;
            ensure!(
                closures
                    .insert(
                        id.clone(),
                        ProducerExecutionProjection {
                            route: RustItemProjection {
                                repo_path: route.repo_path,
                                symbol: route.symbol,
                            },
                            mounted_handler,
                            terminals,
                        },
                    )
                    .is_none(),
                "duplicate producer execution: {id}"
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
    nodes: BTreeMap<String, Vec<ReceiptNode>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TraitMethod {
    trait_name: String,
    method_name: String,
    projection: RustItemProjection,
}

#[derive(Debug, Clone)]
struct ReceiptNode {
    callable_name: String,
    projection: RustItemProjection,
    forwards: BTreeSet<String>,
    port: Option<TraitMethod>,
}

#[derive(Debug, Clone)]
struct PostgresTerminal {
    fact_id: String,
    port_method: TraitMethod,
    provider_method: RustItemProjection,
    transaction: RustItemProjection,
    no_replay: RustItemProjection,
}

#[derive(Debug, Clone)]
struct CanonicalTransactionClosure {
    capability: RustItemProjection,
    append: RustItemProjection,
    settlement: RustItemProjection,
    rollback: RustItemProjection,
    commit_unknown: RustItemProjection,
    rollback_failed: RustItemProjection,
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
                        if !attrs_are_production(&method.attrs) {
                            continue;
                        }
                        for key in receipt_keys_in_signature(&method.sig, aliases) {
                            let projection = RustItemProjection {
                                repo_path: file.repo_path.clone(),
                                symbol: format!("{}::{}", item.ident, method.sig.ident),
                            };
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
                                        projection: projection.clone(),
                                    },
                                );
                            }
                            evidence.nodes.entry(key).or_default().push(ReceiptNode {
                                callable_name: method.sig.ident.to_string(),
                                projection,
                                forwards: BTreeSet::new(),
                                port: Some(TraitMethod {
                                    trait_name: item.ident.to_string(),
                                    method_name: method.sig.ident.to_string(),
                                    projection: RustItemProjection {
                                        repo_path: file.repo_path.clone(),
                                        symbol: format!("{}::{}", item.ident, method.sig.ident),
                                    },
                                }),
                            });
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
                        if !attrs_are_production(&method.attrs) {
                            continue;
                        }
                        for (key, binding) in receipt_bindings_in_signature(&method.sig, aliases) {
                            let forwards = forwarded_call_names(&method.block, &binding);
                            ensure!(
                                !forwards.is_empty(),
                                "{}::{symbol}::{} drops producer receipt `{binding}` instead of forwarding it as a call argument",
                                file.repo_path,
                                method.sig.ident
                            );
                            evidence.carriers.entry(key.clone()).or_default().insert(
                                RustItemProjection {
                                    repo_path: file.repo_path.clone(),
                                    symbol: symbol.clone(),
                                },
                            );
                            evidence.nodes.entry(key).or_default().push(ReceiptNode {
                                callable_name: method.sig.ident.to_string(),
                                projection: RustItemProjection {
                                    repo_path: file.repo_path.clone(),
                                    symbol: format!("{symbol}::{}", method.sig.ident),
                                },
                                forwards,
                                port: None,
                            });
                        }
                    }
                }
                Item::Fn(item) => {
                    if file.repo_path.contains("/internal/") {
                        return Ok(());
                    }
                    for (key, binding) in receipt_bindings_in_signature(&item.sig, aliases) {
                        let forwards = forwarded_call_names(&item.block, &binding);
                        ensure!(
                            !forwards.is_empty(),
                            "{}::{} drops producer receipt `{binding}` instead of forwarding it as a call argument",
                            file.repo_path,
                            item.sig.ident
                        );
                        evidence.carriers.entry(key.clone()).or_default().insert(
                            RustItemProjection {
                                repo_path: file.repo_path.clone(),
                                symbol: item.sig.ident.to_string(),
                            },
                        );
                        evidence.nodes.entry(key).or_default().push(ReceiptNode {
                            callable_name: item.sig.ident.to_string(),
                            projection: RustItemProjection {
                                repo_path: file.repo_path.clone(),
                                symbol: item.sig.ident.to_string(),
                            },
                            forwards,
                            port: None,
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

fn composition_port(method: &TraitMethod) -> Result<ProducerCompositionPort> {
    match method.trait_name.as_str() {
        "AuthGrantLifecycleLocal" => Ok(ProducerCompositionPort::AuthGrantLifecycleLocal),
        "IdentitySecurityLifecycleLocal" => {
            Ok(ProducerCompositionPort::IdentitySecurityLifecycleLocal)
        }
        "PolicyLifecycleLocal" => Ok(ProducerCompositionPort::PolicyLifecycleLocal),
        "RoleBindingLifecycleLocal" => Ok(ProducerCompositionPort::RoleBindingLifecycleLocal),
        "ConfigUnitOfWorkLocal" => Ok(ProducerCompositionPort::ConfigUnitOfWorkLocal),
        other => bail!("active producer reached unsupported production composition port `{other}`"),
    }
}

fn canonical_transaction_closure(root: &Path) -> Result<CanonicalTransactionClosure> {
    let cotx = SourceFile::read(root, &root.join("adapters/postgres/src/cotx/mod.rs"))?;
    let settlement =
        SourceFile::read(root, &root.join("adapters/postgres/src/cotx/settlement.rs"))?;
    let retry = SourceFile::read(root, &root.join("adapters/postgres/src/tx_retry.rs"))?;
    let outbox = SourceFile::read(root, &root.join("adapters/postgres/src/outbox.rs"))?;
    ensure_exact_production_symbol(&cotx, "TxCapability", None)?;
    ensure_exact_production_symbol(&cotx, "finish_local_tx", None)?;
    ensure_exact_production_symbol(&outbox, "append_outbox_with_projection", None)?;
    for method in ["producer_tx", "retry_producer_tx"] {
        ensure_exact_production_symbol(&cotx, "PgWritePool", Some(method))?;
    }
    ensure_canonical_settlement_graph(&cotx)?;
    ensure_exact_production_symbol(&settlement, "LocalTxAttempt", Some("into_retry_result"))?;
    let retry_core = unique_production_function_block(&retry, "run_pg_tx_retry_core")?;
    ensure!(
        exact_method_call_count(retry_core, "into_retry_result") == 1,
        "{}::run_pg_tx_retry_core must consume one LocalTxAttempt through into_retry_result",
        retry.repo_path
    );
    Ok(CanonicalTransactionClosure {
        capability: RustItemProjection {
            repo_path: cotx.repo_path.clone(),
            symbol: "TxCapability".to_string(),
        },
        append: RustItemProjection {
            repo_path: outbox.repo_path,
            symbol: "append_outbox_with_projection".to_string(),
        },
        settlement: RustItemProjection {
            repo_path: cotx.repo_path.clone(),
            symbol: "finish_local_tx".to_string(),
        },
        rollback: RustItemProjection {
            repo_path: cotx.repo_path.clone(),
            symbol: "rollback_local_tx".to_string(),
        },
        commit_unknown: RustItemProjection {
            repo_path: cotx.repo_path.clone(),
            symbol: "finish_local_tx_commit_result".to_string(),
        },
        rollback_failed: RustItemProjection {
            repo_path: cotx.repo_path,
            symbol: "finish_local_tx_rollback_result".to_string(),
        },
    })
}

fn ensure_canonical_settlement_graph(cotx: &SourceFile) -> Result<()> {
    let required_edges = [
        ("producer_tx_inner", "execute_producer_local_tx", 1),
        ("execute_producer_local_tx", "execute_local_tx", 1),
        ("execute_local_tx", "finish_local_tx", 1),
        ("finish_local_tx", "commit_local_tx", 1),
        ("finish_local_tx", "rollback_local_tx", 3),
        ("commit_local_tx", "finish_local_tx_commit_result", 1),
        ("rollback_local_tx", "finish_local_tx_rollback_result", 1),
    ];
    for (caller, callee, expected) in required_edges {
        let block = unique_production_function_block(cotx, caller)?;
        ensure!(
            exact_call_count(block, callee) == expected,
            "{}::{caller} must reach exactly {expected} production `{callee}` call(s)",
            cotx.repo_path,
        );
    }
    Ok(())
}

fn unique_production_function_block<'a>(
    file: &'a SourceFile,
    name: &str,
) -> Result<&'a syn::Block> {
    let blocks = file
        .syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function)
                if function.sig.ident == name && attrs_are_production(&function.attrs) =>
            {
                Some(function.block.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [block] = blocks.as_slice() else {
        bail!(
            "{} must contain one exact production function `{name}`, got {}",
            file.repo_path,
            blocks.len()
        )
    };
    Ok(block)
}

fn exact_call_count(block: &syn::Block, callee: &str) -> usize {
    struct Calls<'a> {
        callee: &'a str,
        count: usize,
    }
    impl Visit<'_> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if attrs_are_production(&call.attrs)
                && call_path_last_ident(&call.func).as_deref() == Some(self.callee)
            {
                self.count += 1;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls { callee, count: 0 };
    calls.visit_block(block);
    calls.count
}

fn exact_method_call_count(block: &syn::Block, method: &str) -> usize {
    struct Calls<'a> {
        method: &'a str,
        count: usize,
    }
    impl Visit<'_> for Calls<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if attrs_are_production(&call.attrs) && call.method == self.method {
                self.count += 1;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut calls = Calls { method, count: 0 };
    calls.visit_block(block);
    calls.count
}

fn ensure_exact_production_symbol(
    file: &SourceFile,
    owner: &str,
    method: Option<&str>,
) -> Result<()> {
    let mut matches = 0usize;
    collect_items(&file.syntax.items, true, &mut |item, production| {
        if !production {
            return Ok(());
        }
        match (item, method) {
            (Item::Struct(item), None) if item.ident == owner => matches += 1,
            (Item::Fn(item), None) if item.sig.ident == owner => matches += 1,
            (Item::Impl(item), Some(method))
                if type_last_ident(&item.self_ty).as_deref() == Some(owner) =>
            {
                matches += item
                    .items
                    .iter()
                    .filter(|member| {
                        matches!(
                            member,
                            syn::ImplItem::Fn(function)
                                if function.sig.ident == method
                                    && attrs_are_production(&function.attrs)
                        )
                    })
                    .count();
            }
            _ => {}
        }
        Ok(())
    })?;
    ensure!(
        matches == 1,
        "{} must contain one exact production symbol {}{}, got {matches}",
        file.repo_path,
        owner,
        method.map_or(String::new(), |method| format!("::{method}"))
    );
    Ok(())
}

fn collect_postgres_terminals(
    files: &[SourceFile],
    traits: &BTreeMap<String, BTreeSet<TraitMethod>>,
    receipt_aliases: &BTreeMap<String, String>,
    expected_fact_aliases: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<BTreeMap<String, Vec<PostgresTerminal>>> {
    let mut by_trait_method = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for (key, methods) in traits {
        for method in methods {
            by_trait_method
                .entry((method.trait_name.clone(), method.method_name.clone()))
                .or_default()
                .insert(key.clone());
        }
    }

    let mut evidence = BTreeMap::<String, Vec<PostgresTerminal>>::new();
    for file in files {
        let callables = provider_callables(file)?;
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
            let Some(trait_name) = trait_path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
            else {
                return Ok(());
            };
            let Some(provider_name) = type_last_ident(&item.self_ty) else {
                return Ok(());
            };
            for method in &item.items {
                let syn::ImplItem::Fn(method) = method else {
                    continue;
                };
                if !attrs_are_production(&method.attrs) {
                    continue;
                }
                let Some(keys) =
                    by_trait_method.get(&(trait_name.clone(), method.sig.ident.to_string()))
                else {
                    continue;
                };
                for key in keys {
                    ensure!(
                        unsafe_no_mutation_count(&method.block) == 0,
                        "{}::{provider_name}::{} uses ProducerTxOutcome::NoMutation outside a proven zero-row/absent-mutation branch",
                        file.repo_path,
                        method.sig.ident
                    );
                    let bindings = receipt_bindings_in_signature(&method.sig, receipt_aliases)
                        .into_iter()
                        .filter_map(|(binding_key, binding)| {
                            (binding_key == *key).then_some(binding)
                        })
                        .collect::<Vec<_>>();
                    ensure!(
                        bindings.len() == 1,
                        "{}::{provider_name}::{} must bind one exact producer receipt for {key}, got {bindings:?}",
                        file.repo_path,
                        method.sig.ident
                    );
                    let expected = expected_fact_aliases.get(key).with_context(|| {
                        format!("producer route {key} has no emitted-fact aliases")
                    })?;
                    let mut event_entries = event_entry_bindings_in_signature(&method.sig);
                    let route_sealed = event_entries.is_empty();
                    if route_sealed && let Some(binding) = route_sealed_command_binding(&method.sig)
                    {
                        event_entries.push(binding);
                    }
                    ensure!(
                        event_entries.len() == 1,
                        "{}::{provider_name}::{} must bind one exact EventEntry, got {event_entries:?}",
                        file.repo_path,
                        method.sig.ident
                    );
                    let authorizations = authorization_bindings(
                        &method.block,
                        &bindings[0],
                        &event_entries[0],
                        expected.values(),
                        route_sealed,
                    );
                    let actual_aliases = authorizations
                        .iter()
                        .map(|(_, alias)| alias.clone())
                        .collect::<BTreeSet<_>>();
                    let expected_aliases = expected.values().cloned().collect::<BTreeSet<_>>();
                    ensure!(
                        actual_aliases == expected_aliases,
                        "{}::{provider_name}::{} producer authorization set mismatch for {key}: expected={expected_aliases:?} actual={actual_aliases:?}",
                        file.repo_path,
                        method.sig.ident
                    );
                    let (transaction_method, authorization_closed, no_replay) =
                        provider_transaction_path(&method.block, &authorizations, &callables)
                            .with_context(|| {
                                format!(
                                    "{}::{provider_name}::{} producer transaction path for {authorizations:?}",
                                    file.repo_path, method.sig.ident,
                                )
                            })?;
                    ensure!(
                        authorization_closed,
                        "{}::{provider_name}::{} authorizes a fact but never returns its token in ProducerTxOutcome::Emitted",
                        file.repo_path,
                        method.sig.ident
                    );
                    let canonical_port = traits
                        .get(key)
                        .and_then(|methods| {
                            methods.iter().find(|candidate| {
                                method.sig.ident == candidate.method_name
                                    && candidate.trait_name.ends_with("Local")
                            })
                        })
                        .with_context(|| {
                            format!(
                                "producer route {key} lacks canonical Local port method for {}",
                                method.sig.ident
                            )
                        })?
                        .clone();
                    let provider_method = RustItemProjection {
                        repo_path: file.repo_path.clone(),
                        symbol: format!("{provider_name}::{}", method.sig.ident),
                    };
                    for (fact_id, alias) in expected {
                        ensure!(
                            authorizations
                                .iter()
                                .any(|(_, authorized_alias)| authorized_alias == alias),
                            "producer route {key} terminal `{fact_id}` lacks exact authorization"
                        );
                        evidence
                            .entry(key.clone())
                            .or_default()
                            .push(PostgresTerminal {
                                fact_id: fact_id.clone(),
                                port_method: canonical_port.clone(),
                                provider_method: provider_method.clone(),
                                transaction: RustItemProjection {
                                    repo_path: "adapters/postgres/src/cotx/mod.rs".to_string(),
                                    symbol: format!("PgWritePool::{transaction_method}"),
                                },
                                no_replay: no_replay.clone(),
                            });
                    }
                }
            }
            Ok(())
        })?;
    }
    for terminals in evidence.values_mut() {
        terminals.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
        for pair in terminals.windows(2) {
            ensure!(
                pair[0].fact_id != pair[1].fact_id,
                "duplicate Postgres producer terminal for fact {}",
                pair[0].fact_id
            );
        }
    }
    Ok(evidence)
}

struct ProviderCallable {
    name: String,
    block: syn::Block,
}

fn provider_callables(file: &SourceFile) -> Result<Vec<ProviderCallable>> {
    let mut callables = Vec::new();
    collect_items(&file.syntax.items, true, &mut |item, production| {
        if production && let Item::Impl(item) = item {
            for member in &item.items {
                if let syn::ImplItem::Fn(method) = member
                    && attrs_are_production(&method.attrs)
                {
                    callables.push(ProviderCallable {
                        name: method.sig.ident.to_string(),
                        block: method.block.clone(),
                    });
                }
            }
        }
        Ok(())
    })?;
    Ok(callables)
}

fn authorization_bindings<'a>(
    block: &syn::Block,
    receipt_binding: &str,
    event_entry_binding: &str,
    expected_aliases: impl Iterator<Item = &'a String>,
    route_sealed: bool,
) -> Vec<(String, String)> {
    #[derive(Clone, Default)]
    struct FactEnvironment {
        scopes: Vec<BTreeMap<String, bool>>,
    }
    impl FactEnvironment {
        fn push(&mut self) {
            self.scopes.push(BTreeMap::new());
        }

        fn pop(&mut self) {
            self.scopes.pop();
        }

        fn declare(&mut self, binding: String, proven: bool) {
            if let Some(scope) = self.scopes.last_mut() {
                scope.insert(binding, proven);
            }
        }

        fn assign(&mut self, binding: &str, proven: bool) {
            if let Some(scope) = self
                .scopes
                .iter_mut()
                .rev()
                .find(|scope| scope.contains_key(binding))
            {
                scope.insert(binding.to_string(), proven);
            }
        }

        fn proven(&self, binding: &str) -> bool {
            self.scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(binding).copied())
                .unwrap_or(false)
        }

        fn merge_definite(base: &Self, branches: &[Self]) -> Self {
            let mut merged = base.clone();
            for (scope_index, scope) in merged.scopes.iter_mut().enumerate() {
                for (binding, proven) in scope {
                    *proven = branches.iter().all(|branch| {
                        branch
                            .scopes
                            .get(scope_index)
                            .and_then(|branch_scope| branch_scope.get(binding))
                            .copied()
                            .unwrap_or(false)
                    });
                }
            }
            merged
        }
    }

    fn pattern_bindings(pattern: &syn::Pat) -> Vec<String> {
        #[derive(Default)]
        struct Bindings {
            names: Vec<String>,
        }
        impl Visit<'_> for Bindings {
            fn visit_pat_ident(&mut self, pattern: &syn::PatIdent) {
                self.names.push(pattern.ident.to_string());
                visit::visit_pat_ident(self, pattern);
            }
        }
        let mut bindings = Bindings::default();
        bindings.visit_pat(pattern);
        bindings.names.sort();
        bindings.names.dedup();
        bindings.names
    }

    fn simple_binding(pattern: &syn::Pat) -> Option<&syn::PatIdent> {
        match pattern {
            syn::Pat::Ident(binding) if binding.subpat.is_none() => Some(binding),
            syn::Pat::Type(pattern) => simple_binding(&pattern.pat),
            syn::Pat::Paren(pattern) => simple_binding(&pattern.pat),
            syn::Pat::Reference(pattern) => simple_binding(&pattern.pat),
            _ => None,
        }
    }

    fn declare_pattern_unproven(environment: &mut FactEnvironment, pattern: &syn::Pat) {
        for binding in pattern_bindings(pattern) {
            environment.declare(binding, false);
        }
    }

    struct Authorizations<'a> {
        receipt_binding: &'a str,
        event_entry_binding: &'a str,
        expected_aliases: BTreeSet<String>,
        route_sealed: bool,
        environment: FactEnvironment,
        found: Vec<(String, String)>,
    }
    impl Authorizations<'_> {
        fn branch(&self) -> Self {
            Self {
                receipt_binding: self.receipt_binding,
                event_entry_binding: self.event_entry_binding,
                expected_aliases: self.expected_aliases.clone(),
                route_sealed: self.route_sealed,
                environment: self.environment.clone(),
                found: Vec::new(),
            }
        }
    }
    impl<'ast> Visit<'ast> for Authorizations<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            self.environment.push();
            for statement in &block.stmts {
                self.visit_stmt(statement);
            }
            self.environment.pop();
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if !attrs_are_production(&local.attrs) {
                return;
            }
            if let Some(initializer) = &local.init {
                let binding = simple_binding(&local.pat);
                if let Some(binding) = binding {
                    for alias in &self.expected_aliases {
                        if expr_contains_authorize(
                            &initializer.expr,
                            self.receipt_binding,
                            alias,
                            self.event_entry_binding,
                            &|name| {
                                self.environment.proven(name)
                                    || (self.route_sealed
                                        && self.expected_aliases.iter().any(|contract| {
                                            contract.strip_suffix("_CONTRACT").is_some_and(
                                                |prefix| name == format!("{prefix}_FACT"),
                                            )
                                        }))
                            },
                        ) {
                            self.found.push((binding.ident.to_string(), alias.clone()));
                        }
                    }
                }
                let proven = binding.is_some()
                    && expr_has_generated_fact_provenance(
                        &initializer.expr,
                        self.event_entry_binding,
                        &|name| self.environment.proven(name),
                    );
                self.visit_expr(&initializer.expr);
                declare_pattern_unproven(&mut self.environment, &local.pat);
                if let Some(binding) = binding {
                    self.environment.declare(binding.ident.to_string(), proven);
                }
                if let Some((_, diverge)) = &initializer.diverge {
                    let mut branch = self.branch();
                    branch.visit_expr(diverge);
                    self.found.extend(branch.found);
                }
            } else {
                declare_pattern_unproven(&mut self.environment, &local.pat);
            }
        }

        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            self.visit_expr(&assignment.right);
            if let syn::Expr::Path(path) = assignment.left.as_ref()
                && path.path.segments.len() == 1
            {
                let binding = path.path.segments[0].ident.to_string();
                let proven = expr_has_generated_fact_provenance(
                    &assignment.right,
                    self.event_entry_binding,
                    &|name| self.environment.proven(name),
                );
                self.environment.assign(&binding, proven);
            }
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            self.visit_expr(&expression.cond);
            let base = self.environment.clone();
            let mut then_branch = self.branch();
            then_branch.environment.push();
            if let syn::Expr::Let(binding) = expression.cond.as_ref() {
                declare_pattern_unproven(&mut then_branch.environment, &binding.pat);
            }
            for statement in &expression.then_branch.stmts {
                then_branch.visit_stmt(statement);
            }
            then_branch.environment.pop();
            let mut branches = vec![then_branch.environment.clone()];
            self.found.extend(then_branch.found);
            if let Some((_, otherwise)) = &expression.else_branch {
                let mut else_branch = self.branch();
                else_branch.visit_expr(otherwise);
                branches.push(else_branch.environment.clone());
                self.found.extend(else_branch.found);
            } else {
                branches.push(base.clone());
            }
            self.environment = FactEnvironment::merge_definite(&base, &branches);
        }

        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            self.visit_expr(&expression.expr);
            let base = self.environment.clone();
            let mut branches = Vec::new();
            for arm in &expression.arms {
                let mut branch = self.branch();
                branch.environment.push();
                declare_pattern_unproven(&mut branch.environment, &arm.pat);
                if let Some((_, guard)) = &arm.guard {
                    branch.visit_expr(guard);
                }
                branch.visit_expr(&arm.body);
                branch.environment.pop();
                branches.push(branch.environment.clone());
                self.found.extend(branch.found);
            }
            if !branches.is_empty() {
                self.environment = FactEnvironment::merge_definite(&base, &branches);
            }
        }

        fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
            let mut branch = self.branch();
            branch.environment.push();
            for input in &expression.inputs {
                declare_pattern_unproven(&mut branch.environment, input);
            }
            branch.visit_expr(&expression.body);
            branch.environment.pop();
            self.found.extend(branch.found);
        }

        fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
            let mut branch = self.branch();
            branch.visit_block(&expression.block);
            self.found.extend(branch.found);
        }

        fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
            self.visit_expr(&expression.expr);
            let base = self.environment.clone();
            let mut body = self.branch();
            body.environment.push();
            declare_pattern_unproven(&mut body.environment, &expression.pat);
            for statement in &expression.body.stmts {
                body.visit_stmt(statement);
            }
            body.environment.pop();
            self.found.extend(body.found);
            self.environment =
                FactEnvironment::merge_definite(&base, &[base.clone(), body.environment]);
        }

        fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
            self.visit_expr(&expression.cond);
            let base = self.environment.clone();
            let mut body = self.branch();
            body.environment.push();
            if let syn::Expr::Let(binding) = expression.cond.as_ref() {
                declare_pattern_unproven(&mut body.environment, &binding.pat);
            }
            for statement in &expression.body.stmts {
                body.visit_stmt(statement);
            }
            body.environment.pop();
            self.found.extend(body.found);
            self.environment =
                FactEnvironment::merge_definite(&base, &[base.clone(), body.environment]);
        }

        fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
            let base = self.environment.clone();
            let mut body = self.branch();
            body.visit_block(&expression.body);
            self.found.extend(body.found);
            self.environment =
                FactEnvironment::merge_definite(&base, &[base.clone(), body.environment]);
        }
    }
    let mut visitor = Authorizations {
        receipt_binding,
        event_entry_binding,
        expected_aliases: expected_aliases.cloned().collect(),
        route_sealed,
        environment: FactEnvironment::default(),
        found: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.found.sort();
    visitor.found.dedup();
    visitor.found
}

fn provider_transaction_path(
    block: &syn::Block,
    authorizations: &[(String, String)],
    callables: &[ProviderCallable],
) -> Result<(String, bool, RustItemProjection)> {
    let direct_transaction = closed_transaction_calls(block, authorizations);
    if !direct_transaction.is_empty() {
        ensure!(
            direct_transaction.len() == 1,
            "provider method must reach one canonical producer transaction, got {direct_transaction:?}"
        );
        let transaction = direct_transaction
            .first()
            .context("transaction call disappeared")?
            .clone();
        let consumer = provider_settlement_consumer(block, &transaction)?;
        return Ok((transaction, true, consumer));
    }

    let helper_names = authorizations
        .iter()
        .flat_map(|(binding, _)| forwarded_call_names(block, binding))
        .collect::<BTreeSet<_>>();
    ensure!(
        helper_names.len() == 1,
        "provider authorization must reach one exact helper or producer transaction, got {helper_names:?}"
    );
    let helper_name = helper_names
        .first()
        .context("provider helper disappeared")?;
    let helpers = callables
        .iter()
        .filter(|callable| callable.name == *helper_name)
        .collect::<Vec<_>>();
    ensure!(
        helpers.len() == 1,
        "provider helper `{helper_name}` must resolve uniquely, got {}",
        helpers.len()
    );
    let transactions = closed_transaction_calls(&helpers[0].block, authorizations);
    ensure!(
        transactions.len() == 1,
        "provider helper `{helper_name}` must reach one awaited producer transaction whose business closure returns its authorization, got {transactions:?}"
    );
    let transaction = transactions
        .first()
        .context("helper transaction disappeared")?
        .clone();
    let consumer = provider_settlement_consumer(&helpers[0].block, &transaction)?;
    Ok((transaction, true, consumer))
}

fn provider_settlement_consumer(
    block: &syn::Block,
    transaction_method: &str,
) -> Result<RustItemProjection> {
    match transaction_method {
        "producer_tx" => {
            struct Consumers {
                count: usize,
            }
            impl Visit<'_> for Consumers {
                fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
                    if attrs_are_production(&call.attrs)
                        && call.method == "into_result"
                        && expression_chain_has_awaited_method(&call.receiver, "producer_tx")
                    {
                        self.count += 1;
                    }
                    visit::visit_expr_method_call(self, call);
                }
            }
            let mut consumers = Consumers { count: 0 };
            consumers.visit_block(block);
            ensure!(
                consumers.count == 1,
                "plain producer transaction must reach exactly one ProducerTxAttempt::into_result consumer, got {}",
                consumers.count
            );
            Ok(RustItemProjection {
                repo_path: "adapters/postgres/src/cotx/mod.rs".to_string(),
                symbol: "ProducerTxAttempt::into_result".to_string(),
            })
        }
        "retry_producer_tx" => {
            ensure!(
                exact_call_count(block, "run_pg_tx_retry") == 1,
                "retry producer transaction must be owned by one run_pg_tx_retry boundary"
            );
            Ok(RustItemProjection {
                repo_path: "adapters/postgres/src/cotx/settlement.rs".to_string(),
                symbol: "LocalTxAttempt::into_retry_result".to_string(),
            })
        }
        other => bail!("unsupported producer transaction consumer for `{other}`"),
    }
}

fn expression_chain_has_awaited_method(expression: &syn::Expr, method: &str) -> bool {
    match expression {
        syn::Expr::Await(awaited) => matches!(
            awaited.base.as_ref(),
            syn::Expr::MethodCall(call) if call.method == method
        ),
        syn::Expr::MethodCall(call) => expression_chain_has_awaited_method(&call.receiver, method),
        syn::Expr::Try(expression) => expression_chain_has_awaited_method(&expression.expr, method),
        syn::Expr::Paren(expression) => {
            expression_chain_has_awaited_method(&expression.expr, method)
        }
        syn::Expr::Group(expression) => {
            expression_chain_has_awaited_method(&expression.expr, method)
        }
        _ => false,
    }
}

fn closed_transaction_calls(
    block: &syn::Block,
    authorizations: &[(String, String)],
) -> BTreeSet<String> {
    struct Transactions<'a> {
        authorization_bindings: BTreeSet<&'a str>,
        calls: BTreeSet<String>,
        executed_callback_depth: usize,
    }
    impl<'ast> Visit<'ast> for Transactions<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            let last = block.stmts.len().saturating_sub(1);
            for (index, statement) in block.stmts.iter().enumerate() {
                match statement {
                    syn::Stmt::Local(local) if attrs_are_production(&local.attrs) => {
                        if let Some(initializer) = &local.init
                            && expression_contains_try(&initializer.expr)
                        {
                            self.visit_expr(&initializer.expr);
                            if let Some((_, diverge)) = &initializer.diverge {
                                self.visit_expr(diverge);
                            }
                        }
                    }
                    syn::Stmt::Expr(expression, semicolon)
                        if (index == last && semicolon.is_none())
                            || expression_contains_try(expression)
                            || matches!(expression, syn::Expr::Return(_)) =>
                    {
                        self.visit_expr(expression);
                    }
                    _ => {}
                }
            }
        }

        fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
            if !attrs_are_production(&expression.attrs) {
                return;
            }
            match expression.base.as_ref() {
                syn::Expr::MethodCall(call)
                    if matches!(
                        call.method.to_string().as_str(),
                        "producer_tx" | "retry_producer_tx"
                    ) =>
                {
                    let is_live_consumer = (call.method == "producer_tx"
                        && self.executed_callback_depth == 0)
                        || (call.method == "retry_producer_tx"
                            && self.executed_callback_depth == 1);
                    if is_live_consumer
                        && transaction_closes_authorization(call, &self.authorization_bindings)
                    {
                        self.calls.insert(call.method.to_string());
                    }
                }
                syn::Expr::Call(call)
                    if call_path_last_ident(&call.func).as_deref() == Some("run_pg_tx_retry") =>
                {
                    for argument in &call.args {
                        let syn::Expr::Closure(callback) = argument else {
                            continue;
                        };
                        self.executed_callback_depth += 1;
                        self.visit_expr(&callback.body);
                        self.executed_callback_depth -= 1;
                    }
                }
                _ => {}
            }
            visit::visit_expr_await(self, expression);
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            self.visit_expr(&expression.cond);
        }

        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            self.visit_expr(&expression.expr);
        }

        fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {}

        fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
            if self.executed_callback_depth > 0 && attrs_are_production(&expression.attrs) {
                self.visit_block(&expression.block);
            }
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }
    let mut visitor = Transactions {
        authorization_bindings: authorizations
            .iter()
            .map(|(binding, _)| binding.as_str())
            .collect(),
        calls: BTreeSet::new(),
        executed_callback_depth: 0,
    };
    visitor.visit_block(block);
    visitor.calls
}

fn expression_contains_try(expression: &syn::Expr) -> bool {
    struct Try {
        found: bool,
    }
    impl Visit<'_> for Try {
        fn visit_expr_try(&mut self, _expression: &syn::ExprTry) {
            self.found = true;
        }

        fn visit_expr_closure(&mut self, _expression: &syn::ExprClosure) {}

        fn visit_expr_async(&mut self, _expression: &syn::ExprAsync) {}
    }
    let mut visitor = Try { found: false };
    visitor.visit_expr(expression);
    visitor.found
}

fn transaction_closes_authorization(
    call: &syn::ExprMethodCall,
    authorization_bindings: &BTreeSet<&str>,
) -> bool {
    let closures = call
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::Expr::Closure(closure) => Some(closure),
            _ => None,
        })
        .collect::<Vec<_>>();
    if closures.len() != 1 {
        return false;
    }
    let Some(block) = boxed_async_closure_block(closures[0]) else {
        return false;
    };
    authorization_bindings
        .iter()
        .any(|binding| block_emits_authorization(block, binding))
}

fn boxed_async_closure_block(closure: &syn::ExprClosure) -> Option<&syn::Block> {
    let body = match closure.body.as_ref() {
        syn::Expr::Block(wrapper)
            if wrapper.block.stmts.len() == 1
                && matches!(wrapper.block.stmts.first(), Some(syn::Stmt::Expr(_, None))) =>
        {
            let Some(syn::Stmt::Expr(expression, None)) = wrapper.block.stmts.first() else {
                return None;
            };
            expression
        }
        expression => expression,
    };
    let syn::Expr::Call(pin) = body else {
        return None;
    };
    if call_path_last_ident(&pin.func).as_deref() != Some("pin") || pin.args.len() != 1 {
        return None;
    }
    match pin.args.first()? {
        syn::Expr::Async(expression) if attrs_are_production(&expression.attrs) => {
            Some(&expression.block)
        }
        _ => None,
    }
}

fn call_path_last_ident(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn block_emits_authorization(block: &syn::Block, binding: &str) -> bool {
    struct Emitted<'a> {
        binding: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Emitted<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if !attrs_are_production(&call.attrs) {
                return;
            }
            if let syn::Expr::Path(path) = call.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Emitted")
                && call
                    .args
                    .iter()
                    .any(|argument| expr_is_ident(argument, self.binding))
            {
                self.found = true;
            }
            visit::visit_expr_call(self, call);
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            self.visit_expr(&expression.cond);
        }

        fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {}

        fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {}

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }
    let mut visitor = Emitted {
        binding,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

fn unsafe_no_mutation_count(block: &syn::Block) -> usize {
    let mutation_outcomes = sql_mutation_outcomes(block);
    let safe_match_bindings = conditional_authorization_bindings(block, &mutation_outcomes);
    let no_mutation_count = exact_call_count(block, "NoMutation");
    if no_mutation_count > 0
        && (mutation_outcomes.len() != 1
            || sql_mutation_await_count(block) != 1
            || opaque_business_await_count(block) != 0)
    {
        return no_mutation_count;
    }
    struct NoMutationGuard<'a> {
        mutation_outcomes: &'a BTreeMap<String, SqlMutationOutcome>,
        safe_match_bindings: BTreeSet<String>,
        safe_depth: usize,
        unsafe_count: usize,
    }
    impl<'ast> Visit<'ast> for NoMutationGuard<'_> {
        fn visit_expr_if(&mut self, expression: &syn::ExprIf) {
            self.visit_expr(&expression.cond);
            let safe = mutation_absent_condition(&expression.cond, self.mutation_outcomes);
            if safe {
                self.safe_depth += 1;
            }
            self.visit_block(&expression.then_branch);
            if safe {
                self.safe_depth -= 1;
            }
            if let Some((_, alternate)) = &expression.else_branch {
                self.visit_expr(alternate);
            }
        }

        fn visit_expr_match(&mut self, expression: &syn::ExprMatch) {
            self.visit_expr(&expression.expr);
            let match_binding = match expression.expr.as_ref() {
                syn::Expr::Path(path) if path.path.segments.len() == 1 => {
                    Some(path.path.segments[0].ident.to_string())
                }
                _ => None,
            };
            for arm in &expression.arms {
                let safe = pat_ident(&arm.pat).as_deref() == Some("None")
                    && match_binding
                        .as_ref()
                        .is_some_and(|binding| self.safe_match_bindings.contains(binding));
                if safe {
                    self.safe_depth += 1;
                }
                if let Some((_, guard)) = &arm.guard {
                    self.visit_expr(guard);
                }
                self.visit_expr(&arm.body);
                if safe {
                    self.safe_depth -= 1;
                }
            }
        }

        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if attrs_are_production(&call.attrs)
                && let syn::Expr::Path(path) = call.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "NoMutation")
                && self.safe_depth == 0
            {
                self.unsafe_count += 1;
            }
            visit::visit_expr_call(self, call);
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }

    let mut guard = NoMutationGuard {
        mutation_outcomes: &mutation_outcomes,
        safe_match_bindings,
        safe_depth: 0,
        unsafe_count: 0,
    };
    guard.visit_block(block);
    guard.unsafe_count
}

fn opaque_business_await_count(block: &syn::Block) -> usize {
    struct OpaqueAwaits {
        count: usize,
    }
    impl Visit<'_> for OpaqueAwaits {
        fn visit_expr_await(&mut self, expression: &syn::ExprAwait) {
            if !attrs_are_production(&expression.attrs) {
                return;
            }
            let allowed = match expression.base.as_ref() {
                syn::Expr::MethodCall(call)
                    if matches!(
                        call.method.to_string().as_str(),
                        "producer_tx" | "retry_producer_tx"
                    ) =>
                {
                    true
                }
                syn::Expr::Call(call)
                    if call_path_last_ident(&call.func).as_deref() == Some("run_pg_tx_retry") =>
                {
                    true
                }
                expression => sql_query_expression(expression),
            };
            if !allowed {
                self.count += 1;
            }
            visit::visit_expr_await(self, expression);
        }

        fn visit_local(&mut self, local: &syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }
    let mut visitor = OpaqueAwaits { count: 0 };
    visitor.visit_block(block);
    visitor.count
}

fn sql_mutation_await_count(block: &syn::Block) -> usize {
    struct MutationAwaits {
        count: usize,
    }
    impl Visit<'_> for MutationAwaits {
        fn visit_expr_await(&mut self, expression: &syn::ExprAwait) {
            if attrs_are_production(&expression.attrs) && sql_mutation_query(&expression.base) {
                self.count += 1;
            }
            visit::visit_expr_await(self, expression);
        }

        fn visit_local(&mut self, local: &syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }
    let mut visitor = MutationAwaits { count: 0 };
    visitor.visit_block(block);
    visitor.count
}

fn sql_query_expression(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::MethodCall(call) => sql_query_expression(&call.receiver),
        syn::Expr::Call(call)
            if matches!(
                call_path_last_ident(&call.func).as_deref(),
                Some("query" | "query_as" | "query_scalar")
            ) =>
        {
            call.args.first().is_some_and(|argument| {
                let syn::Expr::Lit(literal) = argument else {
                    return false;
                };
                let syn::Lit::Str(sql) = &literal.lit else {
                    return false;
                };
                matches!(
                    sql.value()
                        .trim_start()
                        .split_ascii_whitespace()
                        .next()
                        .map(str::to_ascii_uppercase)
                        .as_deref(),
                    Some("SELECT" | "INSERT" | "UPDATE" | "DELETE")
                )
            })
        }
        syn::Expr::Try(expression) => sql_query_expression(&expression.expr),
        syn::Expr::Paren(expression) => sql_query_expression(&expression.expr),
        syn::Expr::Group(expression) => sql_query_expression(&expression.expr),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlMutationOutcome {
    RowsAffected,
    OptionalRow,
}

fn sql_mutation_outcomes(block: &syn::Block) -> BTreeMap<String, SqlMutationOutcome> {
    struct Bindings {
        outcomes: BTreeMap<String, SqlMutationOutcome>,
    }
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if !attrs_are_production(&local.attrs) {
                return;
            }
            if let syn::Pat::Ident(binding) = &local.pat
                && let Some(initializer) = &local.init
                && let Some(outcome) = sql_mutation_outcome(&initializer.expr)
            {
                self.outcomes.insert(binding.ident.to_string(), outcome);
            }
            visit::visit_local(self, local);
        }
    }
    let mut visitor = Bindings {
        outcomes: BTreeMap::new(),
    };
    visitor.visit_block(block);
    visitor.outcomes
}

fn sql_mutation_outcome(expression: &syn::Expr) -> Option<SqlMutationOutcome> {
    if expression_chain_has_sql_terminal(expression, "fetch_optional") {
        Some(SqlMutationOutcome::OptionalRow)
    } else if expression_chain_has_sql_terminal(expression, "execute")
        && expression_chain_projects_rows_affected(expression)
    {
        Some(SqlMutationOutcome::RowsAffected)
    } else {
        None
    }
}

fn expression_chain_has_sql_terminal(expression: &syn::Expr, terminal: &str) -> bool {
    match expression {
        syn::Expr::Await(expression) if attrs_are_production(&expression.attrs) => {
            matches!(
                expression.base.as_ref(),
                syn::Expr::MethodCall(call)
                    if attrs_are_production(&call.attrs)
                        && call.method == terminal
                        && sql_mutation_query(&call.receiver)
            )
        }
        syn::Expr::MethodCall(call)
            if attrs_are_production(&call.attrs)
                && matches!(
                    call.method.to_string().as_str(),
                    "map" | "map_err" | "and_then" | "rows_affected"
                ) =>
        {
            expression_chain_has_sql_terminal(&call.receiver, terminal)
        }
        syn::Expr::Try(expression) => expression_chain_has_sql_terminal(&expression.expr, terminal),
        syn::Expr::Paren(expression) => {
            expression_chain_has_sql_terminal(&expression.expr, terminal)
        }
        syn::Expr::Group(expression) => {
            expression_chain_has_sql_terminal(&expression.expr, terminal)
        }
        _ => false,
    }
}

fn expression_chain_projects_rows_affected(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::MethodCall(call)
            if attrs_are_production(&call.attrs)
                && call.method == "rows_affected"
                && call.args.is_empty() =>
        {
            true
        }
        syn::Expr::MethodCall(call)
            if attrs_are_production(&call.attrs) && call.method == "map" =>
        {
            call.args.iter().any(|argument| {
                let syn::Expr::Closure(closure) = argument else {
                    return false;
                };
                matches!(
                    closure.body.as_ref(),
                    syn::Expr::MethodCall(rows)
                        if attrs_are_production(&rows.attrs)
                            && rows.method == "rows_affected"
                            && rows.args.is_empty()
                )
            })
        }
        syn::Expr::MethodCall(call) if attrs_are_production(&call.attrs) => {
            expression_chain_projects_rows_affected(&call.receiver)
        }
        syn::Expr::Try(expression) => expression_chain_projects_rows_affected(&expression.expr),
        syn::Expr::Paren(expression) => expression_chain_projects_rows_affected(&expression.expr),
        syn::Expr::Group(expression) => expression_chain_projects_rows_affected(&expression.expr),
        _ => false,
    }
}

fn sql_mutation_query(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::MethodCall(call) => sql_mutation_query(&call.receiver),
        syn::Expr::Call(call)
            if matches!(
                call_path_last_ident(&call.func).as_deref(),
                Some("query" | "query_as" | "query_scalar")
            ) =>
        {
            call.args.first().is_some_and(|argument| {
                let syn::Expr::Lit(literal) = argument else {
                    return false;
                };
                let syn::Lit::Str(sql) = &literal.lit else {
                    return false;
                };
                matches!(
                    sql.value()
                        .trim_start()
                        .split_ascii_whitespace()
                        .next()
                        .map(str::to_ascii_uppercase)
                        .as_deref(),
                    Some("INSERT" | "UPDATE" | "DELETE")
                )
            })
        }
        syn::Expr::Paren(expression) => sql_mutation_query(&expression.expr),
        syn::Expr::Group(expression) => sql_mutation_query(&expression.expr),
        _ => false,
    }
}

fn conditional_authorization_bindings(
    block: &syn::Block,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
) -> BTreeSet<String> {
    struct Bindings<'a> {
        mutation_outcomes: &'a BTreeMap<String, SqlMutationOutcome>,
        bindings: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Bindings<'_> {
        fn visit_local(&mut self, local: &syn::Local) {
            if !attrs_are_production(&local.attrs) {
                return;
            }
            if let syn::Pat::Ident(binding) = &local.pat
                && let Some(initializer) = &local.init
                && conditional_authorization(&initializer.expr, self.mutation_outcomes)
            {
                self.bindings.insert(binding.ident.to_string());
            }
            visit::visit_local(self, local);
        }
    }
    let mut visitor = Bindings {
        mutation_outcomes,
        bindings: BTreeSet::new(),
    };
    visitor.visit_block(block);
    visitor.bindings
}

fn conditional_authorization(
    expression: &syn::Expr,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
) -> bool {
    let syn::Expr::If(expression) = expression else {
        return false;
    };
    let Some((_, alternate)) = &expression.else_branch else {
        return false;
    };
    if !mutation_present_condition(&expression.cond, mutation_outcomes) {
        return false;
    }
    struct ThenShape {
        authorize: bool,
        some: bool,
    }
    impl Visit<'_> for ThenShape {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            self.authorize |= call.method == "authorize";
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_path(&mut self, path: &syn::ExprPath) {
            self.some |= path.path.segments.last().is_some_and(|s| s.ident == "Some");
            visit::visit_expr_path(self, path);
        }
    }
    let mut shape = ThenShape {
        authorize: false,
        some: false,
    };
    shape.visit_block(&expression.then_branch);
    shape.authorize && shape.some && expr_is_none(alternate)
}

fn expr_is_none(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Path(path) => path.path.is_ident("None"),
        syn::Expr::Block(block) => block.block.stmts.last().is_some_and(|statement| {
            matches!(statement, syn::Stmt::Expr(expression, _) if expr_is_none(expression))
        }),
        syn::Expr::Paren(expression) => expr_is_none(&expression.expr),
        _ => false,
    }
}

fn mutation_present_condition(
    expression: &syn::Expr,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
) -> bool {
    match expression {
        syn::Expr::MethodCall(call)
            if call.method == "is_some"
                && call.args.is_empty()
                && expr_ident_with_outcome(
                    &call.receiver,
                    mutation_outcomes,
                    SqlMutationOutcome::OptionalRow,
                ) =>
        {
            true
        }
        syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Gt(_)) => {
            binary_ident_zero_with_outcome(
                binary,
                mutation_outcomes,
                SqlMutationOutcome::RowsAffected,
            )
        }
        _ => false,
    }
}

fn mutation_absent_condition(
    expression: &syn::Expr,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
) -> bool {
    matches!(
        expression,
        syn::Expr::Binary(binary)
            if matches!(binary.op, syn::BinOp::Eq(_))
                && binary_ident_zero_with_outcome(
                    binary,
                    mutation_outcomes,
                    SqlMutationOutcome::RowsAffected,
                )
    )
}

fn binary_ident_zero_with_outcome(
    binary: &syn::ExprBinary,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
    expected: SqlMutationOutcome,
) -> bool {
    (expr_is_zero(&binary.left)
        && expr_ident_with_outcome(&binary.right, mutation_outcomes, expected))
        || (expr_is_zero(&binary.right)
            && expr_ident_with_outcome(&binary.left, mutation_outcomes, expected))
}

fn expr_ident_with_outcome(
    expression: &syn::Expr,
    mutation_outcomes: &BTreeMap<String, SqlMutationOutcome>,
    expected: SqlMutationOutcome,
) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.path
        .get_ident()
        .and_then(|ident| mutation_outcomes.get(&ident.to_string()))
        .is_some_and(|outcome| *outcome == expected)
}

fn expr_is_zero(expression: &syn::Expr) -> bool {
    matches!(
        expression,
        syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "0")
    )
}

fn pat_ident(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(pattern) => Some(pattern.ident.to_string()),
        syn::Pat::Path(pattern) => pattern
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn exact_mounted_producer_handler(
    root: &Path,
    source: &str,
    mounted_identity: &str,
    key: &str,
    _domain: &DomainEvidence,
) -> Result<RustItemProjection> {
    let file = SourceFile::read(root, &root.join(source))?;
    let symbol = mounted_identity
        .split("::")
        .last()
        .context("mounted producer handler identity is empty")?;
    let mut matches = Vec::new();
    collect_items(&file.syntax.items, true, &mut |item, production| {
        if production
            && let Item::Fn(function) = item
            && function.sig.ident == symbol
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
            && !handler_receipt_callees(&function.block, &marker_binding).is_empty()
        {
            matches.push(RustItemProjection {
                repo_path: file.repo_path.clone(),
                symbol: symbol.to_string(),
            });
        }
        Ok(())
    })?;
    ensure!(
        matches.len() == 1,
        "mounted producer {key} must resolve exact handler `{mounted_identity}` with one live into_receipt call in {source}, got {matches:?}"
    );
    matches.pop().context("exact mounted handler disappeared")
}

fn reachable_domain_path(
    root: &Path,
    source: &str,
    mounted_identity: &str,
    key: &str,
    domain: &DomainEvidence,
) -> Result<(Vec<RustItemProjection>, TraitMethod)> {
    let file = SourceFile::read(root, &root.join(source))?;
    let symbol = mounted_identity
        .split("::")
        .last()
        .context("mounted producer handler identity is empty")?;
    let mut initial = Vec::new();
    collect_items(&file.syntax.items, true, &mut |item, production| {
        if production
            && let Item::Fn(function) = item
            && function.sig.ident == symbol
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
        {
            initial.extend(handler_receipt_callees(&function.block, &marker_binding));
        }
        Ok(())
    })?;
    initial.sort();
    initial.dedup();
    ensure!(
        initial.len() == 1,
        "mounted producer {key} handler `{mounted_identity}` must forward its receipt through one exact call edge, got {initial:?}"
    );

    let nodes = domain
        .nodes
        .get(key)
        .with_context(|| format!("producer route {key} has no receipt-carrying domain nodes"))?;
    let mut next = initial.pop().context("initial call disappeared")?;
    let mut visited = BTreeSet::new();
    let mut path = Vec::new();
    loop {
        ensure!(
            visited.insert(next.clone()),
            "producer route {key} receipt call graph cycles at `{next}`"
        );
        let candidates = nodes
            .iter()
            .filter(|node| node.callable_name == next)
            .collect::<Vec<_>>();
        ensure!(
            candidates.len() == 1,
            "producer route {key} call edge `{next}` must resolve uniquely, got {:?}",
            candidates
                .iter()
                .map(|node| &node.projection)
                .collect::<Vec<_>>()
        );
        let node = candidates[0];
        if let Some(port) = &node.port {
            ensure!(
                !path.is_empty(),
                "producer route {key} mounted handler bypasses its domain service and calls the UoW port directly"
            );
            return Ok((path, port.clone()));
        }
        path.push(node.projection.clone());
        ensure!(
            node.forwards.len() == 1,
            "producer route {key} node {} must forward its receipt along one exact edge, got {:?}",
            node.projection.symbol,
            node.forwards
        );
        next = node
            .forwards
            .first()
            .context("forwarding edge disappeared")?
            .clone();
    }
}

fn handler_receipt_callees(block: &syn::Block, marker_binding: &str) -> Vec<String> {
    awaited_call_names(block, |argument| {
        expr_contains_into_receipt(argument, marker_binding)
    })
    .into_iter()
    .collect()
}

fn expr_contains_into_receipt(expr: &syn::Expr, marker_binding: &str) -> bool {
    struct IntoReceipt<'a> {
        marker_binding: &'a str,
        found: bool,
    }
    impl Visit<'_> for IntoReceipt<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == "into_receipt"
                && call.args.is_empty()
                && expr_is_ident(&call.receiver, self.marker_binding)
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = IntoReceipt {
        marker_binding,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
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
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut expected = BTreeMap::new();
    for (producer_id, contract) in producers {
        let outbox = contract
            .manifest
            .capabilities
            .outbox
            .as_ref()
            .with_context(|| format!("producer {producer_id} has no outbox capability"))?;
        let mut aliases = BTreeMap::new();
        for fact_id in &outbox.emits {
            let alias = fact_aliases.get(fact_id).with_context(|| {
                format!("producer {producer_id} emits `{fact_id}` without a domain `pub use generated::event::...::CONTRACT as ALIAS`")
            })?;
            ensure!(
                aliases.insert(fact_id.clone(), alias.clone()).is_none(),
                "producer {producer_id} repeats emitted fact `{fact_id}`"
            );
        }
        ensure!(
            !aliases.is_empty(),
            "producer {producer_id} has no emitted facts"
        );
        let generated = crate::codegen::GeneratedCarrier::from_contract(contract)?;
        let key = generated.route_key()?;
        ensure!(
            expected.insert(key.to_string(), aliases).is_none(),
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

fn event_entry_bindings_in_signature(signature: &syn::Signature) -> Vec<String> {
    signature
        .inputs
        .iter()
        .filter_map(|arg| {
            let FnArg::Typed(arg) = arg else { return None };
            let syn::Pat::Ident(binding) = arg.pat.as_ref() else {
                return None;
            };
            (type_last_ident(&arg.ty).as_deref() == Some("EventEntry"))
                .then(|| binding.ident.to_string())
        })
        .collect()
}

/// Recognize the route-specific credential-security proof from the provider signature alone.
/// The named command types have private fields and can only be minted by their exact domain
/// transition; local variable names and statement layout deliberately carry no assurance weight.
fn route_sealed_command_binding(signature: &syn::Signature) -> Option<String> {
    let command_bindings = signature
        .inputs
        .iter()
        .filter_map(|argument| {
            let FnArg::Typed(argument) = argument else {
                return None;
            };
            let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                return None;
            };
            matches!(
                type_last_ident(&argument.ty).as_deref(),
                Some(
                    "LogoutCurrentCommand"
                        | "LogoutAllCommand"
                        | "PasswordChangeCommand"
                        | "AccountStatusSetCommand"
                )
            )
            .then(|| binding.ident.to_string())
        })
        .collect::<Vec<_>>();
    let [command] = command_bindings.as_slice() else {
        return None;
    };
    Some(command.clone())
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

fn forwarded_call_names(block: &syn::Block, binding: &str) -> BTreeSet<String> {
    awaited_call_names(block, |argument| expr_is_ident(argument, binding))
}

fn awaited_call_names(
    block: &syn::Block,
    argument_matches: impl Fn(&syn::Expr) -> bool,
) -> BTreeSet<String> {
    struct LiveAwaitedCalls<F> {
        argument_matches: F,
        callees: BTreeSet<String>,
    }
    impl<'ast, F> Visit<'ast> for LiveAwaitedCalls<F>
    where
        F: Fn(&syn::Expr) -> bool,
    {
        fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
            if !attrs_are_production(&expression.attrs) {
                return;
            }
            match expression.base.as_ref() {
                syn::Expr::Call(call)
                    if attrs_are_production(&call.attrs)
                        && call.args.iter().any(&self.argument_matches) =>
                {
                    if let Some(callee) = call_path_last_ident(&call.func) {
                        self.callees.insert(callee);
                    }
                }
                syn::Expr::MethodCall(call)
                    if attrs_are_production(&call.attrs)
                        && call.args.iter().any(&self.argument_matches) =>
                {
                    self.callees.insert(call.method.to_string());
                }
                _ => {}
            }
            visit::visit_expr_await(self, expression);
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            self.visit_expr(&expression.cond);
        }

        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            self.visit_expr(&expression.expr);
        }

        fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {}

        fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {}

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if attrs_are_production(&local.attrs) {
                visit::visit_local(self, local);
            }
        }
    }
    let mut visitor = LiveAwaitedCalls {
        argument_matches,
        callees: BTreeSet::new(),
    };
    visitor.visit_block(block);
    visitor.callees
}

fn expr_contains_authorize(
    expr: &syn::Expr,
    receipt_binding: &str,
    fact_alias: &str,
    event_entry_binding: &str,
    fact_is_proven: &impl Fn(&str) -> bool,
) -> bool {
    struct ExpectedAuthorize<'a> {
        receipt_binding: &'a str,
        fact_alias: &'a str,
        event_entry_binding: &'a str,
        fact_is_proven: &'a dyn Fn(&str) -> bool,
        found: bool,
    }
    impl Visit<'_> for ExpectedAuthorize<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == "authorize"
                && expr_is_ident(&call.receiver, self.receipt_binding)
                && call.args.len() == 2
                && call.args.first().is_some_and(|argument| {
                    expr_has_generated_fact_provenance(
                        argument,
                        self.event_entry_binding,
                        self.fact_is_proven,
                    )
                })
                && call
                    .args
                    .iter()
                    .nth(1)
                    .is_some_and(|argument| expr_is_ident(argument, self.fact_alias))
            {
                self.found = true;
            }
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_block(&mut self, _expression: &syn::ExprBlock) {}
        fn visit_expr_if(&mut self, _expression: &syn::ExprIf) {}
        fn visit_expr_match(&mut self, _expression: &syn::ExprMatch) {}
        fn visit_expr_closure(&mut self, _expression: &syn::ExprClosure) {}
        fn visit_expr_async(&mut self, _expression: &syn::ExprAsync) {}
        fn visit_expr_for_loop(&mut self, _expression: &syn::ExprForLoop) {}
        fn visit_expr_while(&mut self, _expression: &syn::ExprWhile) {}
        fn visit_expr_loop(&mut self, _expression: &syn::ExprLoop) {}
    }
    let mut visitor = ExpectedAuthorize {
        receipt_binding,
        fact_alias,
        event_entry_binding,
        fact_is_proven,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn expr_has_generated_fact_provenance(
    expr: &syn::Expr,
    event_entry_binding: &str,
    fact_is_proven: &dyn Fn(&str) -> bool,
) -> bool {
    if matches!(expr, syn::Expr::Path(path)
        if path.path.segments.len() == 1
            && fact_is_proven(&path.path.segments[0].ident.to_string()))
    {
        return true;
    }
    match expr {
        syn::Expr::MethodCall(call)
            if call.method == "generated_fact"
                && call.args.is_empty()
                && expr_is_ident(&call.receiver, event_entry_binding) =>
        {
            true
        }
        syn::Expr::MethodCall(call)
            if matches!(call.method.to_string().as_str(), "ok_or" | "ok_or_else")
                && call.args.len() == 1 =>
        {
            expr_has_generated_fact_provenance(&call.receiver, event_entry_binding, fact_is_proven)
        }
        syn::Expr::Try(expression) => expr_has_generated_fact_provenance(
            &expression.expr,
            event_entry_binding,
            fact_is_proven,
        ),
        syn::Expr::Paren(expression) => expr_has_generated_fact_provenance(
            &expression.expr,
            event_entry_binding,
            fact_is_proven,
        ),
        syn::Expr::Group(expression) => expr_has_generated_fact_provenance(
            &expression.expr,
            event_entry_binding,
            fact_is_proven,
        ),
        _ => false,
    }
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
        attribute.path().is_ident("test")
            || ((attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
                && token_stream_contains_test(quote::ToTokens::to_token_stream(&attribute.meta)))
    })
}

fn token_stream_contains_test(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => ident == "test",
        proc_macro2::TokenTree::Group(group) => token_stream_contains_test(group.stream()),
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
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
            exact_mounted_producer_handler(
                &fixture.path,
                "crates/settings/src/application.rs",
                "handler",
                "settings_v1",
                &DomainEvidence::default(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn mounted_receipt_in_dead_or_unawaited_expression_is_rejected() -> anyhow::Result<()> {
        let dead: syn::Block = syn::parse_str(
            r#"{
                if false {
                    service(marker.into_receipt()).await;
                }
            }"#,
        )?;
        assert!(
            handler_receipt_callees(&dead, "marker").is_empty(),
            "a receipt edge hidden below `if false` is not live execution evidence"
        );

        let unawaited: syn::Block = syn::parse_str(
            r#"{
                let _future = service(marker.into_receipt());
            }"#,
        )?;
        assert!(
            handler_receipt_callees(&unawaited, "marker").is_empty(),
            "constructing but not awaiting a receipt-carrying future is not execution evidence"
        );
        Ok(())
    }

    #[test]
    fn ambiguous_execution_call_edge_is_rejected() -> anyhow::Result<()> {
        let fixture = TempRoot::new("ambiguous-call-edge")?;
        let source = fixture.path.join("crates/settings/src/application.rs");
        fs::create_dir_all(source.parent().context("source parent")?)?;
        fs::write(
            &source,
            r#"
            async fn handler(
                marker: httpserve::ProducerMarker<generated::http::settings_v1::RouteMarker>,
            ) {
                service(marker.into_receipt()).await;
            }
            "#,
        )?;
        let projection = |symbol: &str| ReceiptNode {
            callable_name: "service".to_string(),
            projection: RustItemProjection {
                repo_path: "crates/settings/src/application.rs".to_string(),
                symbol: symbol.to_string(),
            },
            forwards: BTreeSet::from(["commit".to_string()]),
            port: None,
        };
        let domain = DomainEvidence {
            nodes: BTreeMap::from([(
                "settings_v1".to_string(),
                vec![
                    projection("FirstService::service"),
                    projection("Decoy::service"),
                ],
            )]),
            ..DomainEvidence::default()
        };
        assert!(
            reachable_domain_path(
                &fixture.path,
                "crates/settings/src/application.rs",
                "handler",
                "settings_v1",
                &domain,
            )
            .is_err(),
            "ambiguous live/decoy call edges must fail closed"
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
    fn sealed_identity_security_command_proof_depends_only_on_the_route_specific_signature()
    -> anyhow::Result<()> {
        for command in [
            "LogoutCurrentCommand",
            "LogoutAllCommand",
            "PasswordChangeCommand",
            "AccountStatusSetCommand",
        ] {
            let canonical: syn::ItemFn = syn::parse_str(&format!(
                "async fn execute(command: identity::ports::{command}) {{ helper(command).await }}"
            ))?;
            assert_eq!(
                route_sealed_command_binding(&canonical.sig).as_deref(),
                Some("command"),
                "{command} must remain a route-sealed producer command"
            );
        }

        for source in [
            r#"
            async fn execute(command: identity::ports::CredentialSecurityCommand) {
                let fact = identity::ports::credential_security_fact(command.event())?;
                let entry = fact.entry().clone();
            }
            "#,
            r#"
            async fn execute(
                current: identity::ports::LogoutCurrentCommand,
                all: identity::ports::LogoutAllCommand,
            ) {}
            "#,
            r#"
            async fn execute(command: identity::ports::ReactivateAccountCommand) {}
            "#,
        ] {
            let rejected: syn::ItemFn = syn::parse_str(source)?;
            assert!(
                route_sealed_command_binding(&rejected.sig).is_none(),
                "generic or ambiguous command signatures must fail closed"
            );
        }

        let layout_independent: syn::ItemFn = syn::parse_str(
            r#"
            async fn renamed_and_delegated(
                exact: identity::ports::LogoutAllCommand,
            ) {
                helper(exact).await
            }
            "#,
        )?;
        assert_eq!(
            route_sealed_command_binding(&layout_independent.sig).as_deref(),
            Some("exact"),
            "proof must not depend on local names, clone calls, or top-level statement layout"
        );
        Ok(())
    }

    #[test]
    fn workspace_identity_security_producer_commands_are_exact_and_non_vacuous()
    -> anyhow::Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must live below the workspace root")?;
        let source = fs::read_to_string(root.join("crates/identity/src/ports.rs"))?;
        let syntax = syn::parse_file(&source)?;
        let lifecycle = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Trait(item) if item.ident == "IdentitySecurityLifecycleLocal" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [lifecycle] = lifecycle.as_slice() else {
            bail!("workspace must contain one IdentitySecurityLifecycleLocal trait")
        };
        let methods = lifecycle
            .items
            .iter()
            .filter_map(|item| match item {
                syn::TraitItem::Fn(method) => Some(method),
                _ => None,
            })
            .map(|method| {
                (
                    method.sig.ident.to_string(),
                    route_sealed_command_binding(&method.sig),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(
            methods
                .get("execute_password_change")
                .is_some_and(Option::is_some)
        );
        assert!(
            methods
                .get("execute_account_status_set")
                .is_some_and(Option::is_some)
        );
        assert!(!methods.contains_key("execute_reactivation"));
        assert_eq!(
            methods
                .iter()
                .filter_map(|(method, command)| command.as_ref().map(|_| method.as_str()))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "execute_account_status_set",
                "execute_logout_all",
                "execute_logout_current",
                "execute_password_change",
            ]),
            "the route-sealed identity-security producer method set must remain exact"
        );
        let reactivation = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Trait(item) if item.ident == "AccountReactivationLifecycleLocal" => {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [reactivation] = reactivation.as_slice() else {
            bail!("workspace must contain one AccountReactivationLifecycleLocal trait")
        };
        assert_eq!(reactivation.items.len(), 1);
        assert!(matches!(
            &reactivation.items[0],
            syn::TraitItem::Fn(method) if method.sig.ident == "execute_reactivation"
        ));
        Ok(())
    }

    #[test]
    fn postgres_provider_without_producer_tx_is_rejected() -> anyhow::Result<()> {
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
                    let authorization = receipt
                        .authorize(generated_fact, CONFIG_VERSION_CHANGED_CONTRACT)
                        .unwrap();
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
        let evidence = collect_postgres_terminals(
            &[postgres_file],
            &domain.traits,
            &aliases,
            &BTreeMap::from([(
                "settings_v1".into(),
                BTreeMap::from([(
                    "settings.config-version-changed".into(),
                    "CONFIG_VERSION_CHANGED_CONTRACT".into(),
                )]),
            )]),
        );
        assert!(
            evidence.is_err(),
            "authorization without the canonical producer transaction funnel must fail closed"
        );
        Ok(())
    }

    #[test]
    fn producer_transaction_must_be_unconditional_awaited_and_authorization_closed_inside_it()
    -> anyhow::Result<()> {
        let authorization = vec![(
            "authorization".to_string(),
            "EXACT_FACT_CONTRACT".to_string(),
        )];

        let unawaited: syn::Block = syn::parse_str(
            r#"{
                self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                );
            }"#,
        )?;
        assert!(
            provider_transaction_path(&unawaited, &authorization, &[]).is_err(),
            "an unawaited producer transaction future must not close execution"
        );

        let ignored: syn::Block = syn::parse_str(
            r#"{
                let _ignored = self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await;
                Ok(())
            }"#,
        )?;
        assert!(
            provider_transaction_path(&ignored, &authorization, &[]).is_err(),
            "an awaited transaction whose Result is discarded must not close execution"
        );

        let conditional: syn::Block = syn::parse_str(
            r#"{
                if false {
                    self.pool.producer_tx(
                        scope,
                        &entry,
                        &env,
                        move |conn| Box::pin(async move {
                            write_business(conn.conn()).await?;
                            Ok(ProducerTxOutcome::Emitted((), authorization))
                        }),
                        storage,
                    ).await?;
                }
            }"#,
        )?;
        assert!(
            provider_transaction_path(&conditional, &authorization, &[]).is_err(),
            "a conditionally unreachable producer transaction must not close execution"
        );

        let separated: syn::Block = syn::parse_str(
            r#"{
                self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::NoMutation(()))
                    }),
                    storage,
                ).await?;
                Ok(ProducerTxOutcome::Emitted((), authorization))
            }"#,
        )?;
        assert!(
            provider_transaction_path(&separated, &authorization, &[]).is_err(),
            "Emitted outside the transaction business closure must not close authorization"
        );

        let direct: syn::Block = syn::parse_str(
            r#"{
                self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await
            }"#,
        )?;
        assert!(
            provider_transaction_path(&direct, &authorization, &[]).is_err(),
            "a plain producer transaction without its actual settlement consumer is incomplete"
        );

        let settlement_preserved: syn::Block = syn::parse_str(
            r#"{
                let value = self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await.into_result()?;
                Ok(value)
            }"#,
        )?;
        assert_eq!(
            provider_transaction_path(&settlement_preserved, &authorization, &[])?.0,
            "producer_tx"
        );

        let retry_helper: syn::Block = syn::parse_str(
            r#"{
                run_pg_tx_retry(
                    BOUNDARY,
                    |_attempt, deadline| {
                        async move {
                            self.pool.retry_producer_tx(
                                scope,
                                deadline,
                                &entry,
                                &env,
                                move |conn| Box::pin(async move {
                                    write_business(conn.conn()).await?;
                                    Ok(ProducerTxOutcome::Emitted((), authorization))
                                }),
                                storage,
                            ).await
                        }
                    },
                    classify,
                ).await
            }"#,
        )?;
        assert_eq!(
            provider_transaction_path(&retry_helper, &authorization, &[])?.0,
            "retry_producer_tx"
        );

        let unrelated_retry_runner: syn::Block = syn::parse_str(
            r#"{
                self.pool.retry_producer_tx(
                    scope,
                    deadline,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await?;
                run_pg_tx_retry(
                    BOUNDARY,
                    |_attempt, _deadline| async move { unrelated_attempt() },
                    classify,
                ).await
            }"#,
        )?;
        assert!(
            provider_transaction_path(&unrelated_retry_runner, &authorization, &[]).is_err(),
            "an unrelated retry runner cannot lend its settlement consumer to a retry producer outside that runner's operation"
        );
        Ok(())
    }

    #[test]
    fn test_only_provider_members_and_statements_are_not_execution_evidence() -> anyhow::Result<()>
    {
        let file = SourceFile {
            repo_path: "adapters/postgres/src/provider.rs".into(),
            syntax: syn::parse_file(
                r#"
                impl PgProvider {
                    #[cfg(test)]
                    async fn producer_helper(&self) {
                        self.pool.producer_tx(
                            scope,
                            &entry,
                            &env,
                            move |conn| Box::pin(async move {
                                write_business(conn.conn()).await?;
                                Ok(ProducerTxOutcome::Emitted((), authorization))
                            }),
                            storage,
                        ).await
                    }
                }
                "#,
            )?,
        };
        assert!(
            provider_callables(&file)?.is_empty(),
            "a cfg(test) impl member is not a production helper"
        );

        let block: syn::Block = syn::parse_str(
            r#"{
                #[cfg(test)]
                let authorization = receipt
                    .authorize(generated_fact, EXACT_FACT_CONTRACT)
                    .unwrap();
                self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await
            }"#,
        )?;
        assert!(
            authorization_bindings(
                &block,
                "receipt",
                "entry",
                std::iter::once(&"EXACT_FACT_CONTRACT".to_string()),
                false,
            )
            .is_empty(),
            "a cfg(test) local must not mint production authorization evidence"
        );

        let test_only_transaction: syn::Block = syn::parse_str(
            r#"{
                #[cfg(test)]
                self.pool.producer_tx(
                    scope,
                    &entry,
                    &env,
                    move |conn| Box::pin(async move {
                        write_business(conn.conn()).await?;
                        Ok(ProducerTxOutcome::Emitted((), authorization))
                    }),
                    storage,
                ).await;
            }"#,
        )?;
        let authorization = vec![(
            "authorization".to_string(),
            "EXACT_FACT_CONTRACT".to_string(),
        )];
        assert!(
            provider_transaction_path(&test_only_transaction, &authorization, &[]).is_err(),
            "a cfg(test) statement is not a production transaction"
        );
        Ok(())
    }

    #[test]
    fn no_mutation_requires_a_proven_absent_business_mutation_branch() -> anyhow::Result<()> {
        let unsafe_success: syn::Block = syn::parse_str(
            r#"{
                write_business_row(conn).await?;
                Ok(ProducerTxOutcome::NoMutation(()))
            }"#,
        )?;
        assert_eq!(unsafe_no_mutation_count(&unsafe_success), 1);

        let zero_rows: syn::Block = syn::parse_str(
            r#"{
                let deleted = sqlx::query("DELETE FROM records WHERE id = $1")
                    .bind(id)
                    .execute(conn)
                    .await?
                    .rows_affected();
                if deleted == 0 {
                    return Ok(ProducerTxOutcome::NoMutation(false));
                }
                Ok(ProducerTxOutcome::Emitted(true, authorization))
            }"#,
        )?;
        assert_eq!(unsafe_no_mutation_count(&zero_rows), 0);

        let optional_row: syn::Block = syn::parse_str(
            r#"{
                let row = sqlx::query("UPDATE records SET value = $1 WHERE id = $2 RETURNING id")
                    .bind(value)
                    .bind(id)
                    .fetch_optional(conn)
                    .await?;
                let authorization = if row.is_some() {
                    let authorization = receipt.authorize(generated_fact, EXACT_FACT).unwrap();
                    Some(authorization)
                } else {
                    None
                };
                Ok(match authorization {
                    Some(authorization) => ProducerTxOutcome::Emitted(value, authorization),
                    None => ProducerTxOutcome::NoMutation(value),
                })
            }"#,
        )?;
        assert_eq!(unsafe_no_mutation_count(&optional_row), 0);

        let unrelated_zero: syn::Block = syn::parse_str(
            r#"{
                let fake = 0;
                if fake == 0 {
                    return Ok(ProducerTxOutcome::NoMutation(false));
                }
                Ok(ProducerTxOutcome::Emitted(true, authorization))
            }"#,
        )?;
        assert_eq!(
            unsafe_no_mutation_count(&unrelated_zero),
            1,
            "an arbitrary zero-valued local is not a SQL mutation outcome"
        );

        let unrelated_option: syn::Block = syn::parse_str(
            r#"{
                let row = cache_lookup();
                let authorization = if row.is_some() {
                    Some(receipt.authorize(generated_fact, EXACT_FACT).unwrap())
                } else {
                    None
                };
                Ok(match authorization {
                    Some(authorization) => ProducerTxOutcome::Emitted(value, authorization),
                    None => ProducerTxOutcome::NoMutation(value),
                })
            }"#,
        )?;
        assert_eq!(
            unsafe_no_mutation_count(&unrelated_option),
            1,
            "an arbitrary Option is not a SQL mutation outcome"
        );

        let wrong_else: syn::Block = syn::parse_str(
            r#"{
                let deleted = sqlx::query("DELETE FROM records WHERE id = $1")
                    .bind(id)
                    .execute(conn)
                    .await?
                    .rows_affected();
                if deleted == 0 {
                    recover();
                } else {
                    return Ok(ProducerTxOutcome::NoMutation(false));
                }
                Ok(ProducerTxOutcome::Emitted(true, authorization))
            }"#,
        )?;
        assert_eq!(
            unsafe_no_mutation_count(&wrong_else),
            1,
            "only the zero-row then branch may return NoMutation"
        );

        let mapped_rows: syn::Block = syn::parse_str(
            r#"{
                let rows = sqlx::query("UPDATE records SET deleted = true WHERE id = $1")
                    .bind(id)
                    .execute(conn)
                    .await
                    .map_err(storage)
                    .map(|result| result.rows_affected())?;
                let authorization = if rows > 0 {
                    Some(receipt.authorize(generated_fact, EXACT_FACT).unwrap())
                } else {
                    None
                };
                Ok(match authorization {
                    Some(authorization) => ProducerTxOutcome::Emitted(rows, authorization),
                    None => ProducerTxOutcome::NoMutation(rows),
                })
            }"#,
        )?;
        assert_eq!(unsafe_no_mutation_count(&mapped_rows), 0);

        let decoy_sql_outcome: syn::Block = syn::parse_str(
            r#"{
                write_business_row(conn).await?;
                let decoy_rows = sqlx::query("DELETE FROM decoy WHERE id = $1")
                    .bind(id)
                    .execute(conn)
                    .await?
                    .rows_affected();
                if decoy_rows == 0 {
                    return Ok(ProducerTxOutcome::NoMutation(false));
                }
                Ok(ProducerTxOutcome::Emitted(true, authorization))
            }"#,
        )?;
        assert_eq!(
            unsafe_no_mutation_count(&decoy_sql_outcome),
            1,
            "an unrelated zero-row SQL outcome must not prove that an opaque business mutation was absent"
        );

        let discarded_business_mutation: syn::Block = syn::parse_str(
            r#"{
                sqlx::query("INSERT INTO records(id) VALUES ($1)")
                    .bind(id)
                    .execute(conn)
                    .await?;
                let decoy_rows = sqlx::query("DELETE FROM decoy WHERE id = $1")
                    .bind(id)
                    .execute(conn)
                    .await?
                    .rows_affected();
                if decoy_rows == 0 {
                    return Ok(ProducerTxOutcome::NoMutation(false));
                }
                Ok(ProducerTxOutcome::Emitted(true, authorization))
            }"#,
        )?;
        assert_eq!(
            unsafe_no_mutation_count(&discarded_business_mutation),
            1,
            "a discarded direct SQL mutation cannot be hidden behind another zero-row outcome"
        );
        Ok(())
    }

    #[test]
    fn authorization_fact_provenance_is_semantic_not_a_local_name() -> anyhow::Result<()> {
        let sealed_direct: syn::Block = syn::parse_str(
            r#"{
                let authorization = receipt
                    .authorize(SECURITY_EVENT_FACT, SECURITY_EVENT_CONTRACT)
                    .ok_or_else(storage)?;
            }"#,
        )?;
        assert_eq!(
            authorization_bindings(
                &sealed_direct,
                "receipt",
                "command",
                std::iter::once(&"SECURITY_EVENT_CONTRACT".to_string()),
                true,
            ),
            [(
                "authorization".to_string(),
                "SECURITY_EVENT_CONTRACT".to_string()
            )],
            "an exact route-sealed command admits only the fact alias derived from its manifest contract"
        );

        let renamed: syn::Block = syn::parse_str(
            r#"{
                let fact = entry.generated_fact().ok_or_else(storage)?;
                let authorization = receipt
                    .authorize(fact, EXACT_FACT)
                    .ok_or_else(storage)?;
            }"#,
        )?;
        assert!(
            authorization_bindings(
                &renamed,
                "receipt",
                "entry",
                std::iter::once(&"EXACT_FACT".to_string()),
                false,
            ) == [("authorization".to_string(), "EXACT_FACT".to_string())],
            "renaming a binding derived from EventEntry::generated_fact must preserve evidence"
        );

        let decoy: syn::Block = syn::parse_str(
            r#"{
                let generated_fact = unrelated_fact;
                let authorization = receipt
                    .authorize(generated_fact, EXACT_FACT)
                    .ok_or_else(storage)?;
            }"#,
        )?;
        assert!(
            authorization_bindings(
                &decoy,
                "receipt",
                "entry",
                std::iter::once(&"EXACT_FACT".to_string()),
                false,
            )
            .is_empty(),
            "a magic local name without EventEntry::generated_fact provenance is not evidence"
        );

        let mixed: syn::Block = syn::parse_str(
            r#"{
                let fact = choose(entry.generated_fact(), forged_fact);
                let authorization = receipt
                    .authorize(fact, EXACT_FACT)
                    .ok_or_else(storage)?;
            }"#,
        )?;
        assert!(
            authorization_bindings(
                &mixed,
                "receipt",
                "entry",
                std::iter::once(&"EXACT_FACT".to_string()),
                false,
            )
            .is_empty(),
            "a mixed-source expression that merely contains generated_fact is not provenance"
        );

        for (case, source) in [
            (
                "shadow",
                r#"{
                    let fact = entry.generated_fact().ok_or_else(storage)?;
                    {
                        let fact = forged_fact;
                        let authorization = receipt
                            .authorize(fact, EXACT_FACT)
                            .ok_or_else(storage)?;
                    }
                }"#,
            ),
            (
                "reassign",
                r#"{
                    let mut fact = entry.generated_fact().ok_or_else(storage)?;
                    fact = forged_fact;
                    let authorization = receipt
                        .authorize(fact, EXACT_FACT)
                        .ok_or_else(storage)?;
                }"#,
            ),
            (
                "branch_merge",
                r#"{
                    let mut fact = entry.generated_fact().ok_or_else(storage)?;
                    if replace_fact {
                        fact = forged_fact;
                    }
                    let authorization = receipt
                        .authorize(fact, EXACT_FACT)
                        .ok_or_else(storage)?;
                }"#,
            ),
            (
                "typed_shadow",
                r#"{
                    let fact = entry.generated_fact().ok_or_else(storage)?;
                    let fact: FactBinding = forged_fact;
                    let authorization = receipt
                        .authorize(fact, EXACT_FACT)
                        .ok_or_else(storage)?;
                }"#,
            ),
            (
                "closure_parameter_shadow",
                r#"{
                    let fact = entry.generated_fact().ok_or_else(storage)?;
                    let authorize = |fact| {
                        let authorization = receipt
                            .authorize(fact, EXACT_FACT)
                            .ok_or_else(storage)?;
                    };
                }"#,
            ),
        ] {
            let block: syn::Block = syn::parse_str(source)?;
            assert!(
                authorization_bindings(
                    &block,
                    "receipt",
                    "entry",
                    std::iter::once(&"EXACT_FACT".to_string()),
                    false,
                )
                .is_empty(),
                "{case} must invalidate the old generated-fact binding"
            );
        }

        let all_branches_proven: syn::Block = syn::parse_str(
            r#"{
                let mut fact = entry.generated_fact().ok_or_else(storage)?;
                if refresh_fact {
                    fact = entry.generated_fact().ok_or_else(storage)?;
                } else {
                    fact = entry.generated_fact().ok_or_else(storage)?;
                }
                let authorization = receipt
                    .authorize(fact, EXACT_FACT)
                    .ok_or_else(storage)?;
            }"#,
        )?;
        assert_eq!(
            authorization_bindings(
                &all_branches_proven,
                "receipt",
                "entry",
                std::iter::once(&"EXACT_FACT".to_string()),
                false,
            ),
            [("authorization".to_string(), "EXACT_FACT".to_string())],
            "branch merge may retain provenance only when every incoming definition is generated"
        );
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
