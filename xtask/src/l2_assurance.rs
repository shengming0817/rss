//! Deterministic active-L2 producer/fact assurance inventory.
//!
//! INVARIANT: L2-ASSURANCE-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private role-specific evidence construction plus closed Role, CarrierKind, ClosedStatus, and EvidenceStatus types make incomplete or caller-authored status records unrepresentable" }——
//! producer and fact records have distinct closed evidence types. A producer can only be authored
//! with contract/generated/execution/fault；fact effect evidence 则由 active subscription 动态发现
//! registration/plan/handler/executor 四阶段真实 carrier，generated SPEC 不得冒充执行证据。
//! INVARIANT: L2-ASSURANCE-CONSUMER-POLICY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::policy_carrier_rejects_dead_helper_bait + tests::policy_carrier_rejects_nested_dead_helper_bait + tests::policy_carrier_rejects_if_false_bait + tests::policy_executor_rejects_symbol_without_worker_edge", anti_vacuity = "tests::workspace_fact_effect_evidence_closes_all_policy_stages" }——
//! active ConsumerTx handler 集合从 generated subscriptions 计算；每条 subscription identity
//! 必须映射到 registration/plan/handler/executor 的精确 Rust symbol 与闭合调用链，任意死 helper 不得冒充。
//! INVARIANT: L2-ASSURANCE-WIRE-01 { level = "Hard", exec = "check", source = "codegen", golden = "generated/l2-assurance.json", synthetic_red = "tests::check_rejects_missing_tampered_and_crlf_without_writing", anti_vacuity = "tests::workspace_inventory_is_exact_and_deterministic" }——
//! the typed JSON v3 projection and committed golden are byte-for-byte deterministic and reject
//! missing, tampered, or non-LF output without writing in check mode.
//! INVARIANT: L2-ASSURANCE-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::exact_set_rejects_equal_size_wrong_identity", anti_vacuity = "tests::workspace_inventory_is_exact_and_deterministic" }——
//! active OutboxFact manifests, generated registries, producer execution terminals and named fault
//! cases are joined bidirectionally; each producer terminal fact set equals manifest `emits`, while
//! producer/fact non-empty anti-vacuity is enforced by the same typed inventory used to render the
//! committed assurance artifact; rustdoc does not duplicate live catalog counts.
//! INVARIANT: L2-ASSURANCE-PATH-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::carrier_paths_reject_escapes_backslashes_and_symlinks", anti_vacuity = "tests::workspace_inventory_is_exact_and_deterministic" }——
//! every carrier and the fixed output are real repository-local paths without symlink traversal.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::marker::PhantomData;
use std::path::{Component, Path};

use crate::contract::GovernedContract;
use anyhow::{Context, Result, bail, ensure};
use assembly_schema::contract_manifest::{
    ConsistencyLevel, ContractKind, EffectKind,
    ExternalEffectPolicy as ManifestExternalEffectPolicy, Lifecycle, OutboxRole,
    SubscriptionEffect as ManifestSubscriptionEffect,
    SubscriptionExecution as ManifestSubscriptionExecution,
};
use generated::event::{
    SubscriptionEffect as GeneratedSubscriptionEffect,
    SubscriptionExecution as GeneratedSubscriptionExecution,
};
use serde::Serialize;
use syn::visit::Visit;
use vocab::{
    ExternalEffectPolicy as GeneratedExternalEffectPolicy, HttpConsistencyLevel, HttpEffectKind,
};

use crate::{
    consistency_fixtures, contract, event_transport_guard, generated_file, producer_assurance,
};

const OUTPUT: &str = "generated/l2-assurance.json";
const LF_DECLARATION: &str = "generated/l2-assurance.json text eol=lf";
const MAX_RUST_CARRIER_BYTES: u64 = 2 * 1024 * 1024;

/// Generate or raw-byte check the only committed L2 assurance artifact.
pub(crate) fn run(
    root: &Path,
    workspace_facts: &workspacefacts::WorkspaceFacts,
    check: bool,
) -> Result<()> {
    let output = root.join(OUTPUT);
    validate_output_path(root, &output)?;
    generated_file::verify_lf_checkout(root, LF_DECLARATION, std::slice::from_ref(&output))
        .map_err(lf_checkout_error)?;
    let bytes = render(&build_inventory(root, workspace_facts)?)?;
    if check {
        return check_rendered_file(&output, &bytes);
    }
    generated_file::atomic_replace(&output, &bytes)
}

fn lf_checkout_error(stage: generated_file::LfCheckoutFailure) -> anyhow::Error {
    let detail = match stage {
        generated_file::LfCheckoutFailure::AttributesRead => {
            "cannot read repository .gitattributes"
        }
        generated_file::LfCheckoutFailure::DeclarationMismatch => {
            "expected exactly one `generated/l2-assurance.json text eol=lf` declaration"
        }
        generated_file::LfCheckoutFailure::Input => {
            "the fixed generated/l2-assurance.json target is not repository-local"
        }
        generated_file::LfCheckoutFailure::GitInvocation => {
            "`/usr/bin/git check-attr` failed or returned an invalid response"
        }
        generated_file::LfCheckoutFailure::EffectivePolicyMismatch => {
            "effective Git attributes for generated/l2-assurance.json are not `text eol=lf`"
        }
    };
    anyhow::anyhow!(
        "L2 assurance LF checkout policy failed: {detail}; restore `.gitattributes`, then run `./hack/cargo.sh xtask l2-assurance`"
    )
}

fn build_inventory(
    root: &Path,
    workspace_facts: &workspacefacts::WorkspaceFacts,
) -> Result<Inventory> {
    let governance = contract::governance::ContractGovernanceIr::load_consumer_workspace(root)?;
    governance.read(|contracts| build_inventory_from_contracts(root, workspace_facts, contracts))
}

fn build_inventory_from_contracts(
    root: &Path,
    workspace_facts: &workspacefacts::WorkspaceFacts,
    contracts: &[GovernedContract],
) -> Result<Inventory> {
    let (_, transport_findings) = event_transport_guard::check_root(root)?;
    ensure_findings_empty("event transport closure", &transport_findings)?;

    let universe = classify_active_l2(contracts)?;
    ensure!(
        !universe.producers.is_empty(),
        "active L2 producer inventory is empty"
    );
    ensure!(
        !universe.facts.is_empty(),
        "active L2 fact inventory is empty"
    );
    let emitted_fact_ids = universe
        .producers
        .values()
        .flat_map(|contract| {
            contract
                .manifest()
                .capabilities
                .outbox
                .iter()
                .flat_map(|outbox| outbox.emits.iter())
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure_exact_ids(
        "active L2 fact/producer emits union",
        universe.facts.keys(),
        emitted_fact_ids.iter(),
    )?;

    let http_specs = generated_http_specs()?;
    ensure_exact_ids(
        "active L2 producer manifest/generated",
        universe.producers.keys(),
        http_specs.keys(),
    )?;
    let event_specs = generated_event_specs()?;
    ensure_exact_ids(
        "active L2 fact manifest/generated",
        universe.facts.keys(),
        event_specs.keys(),
    )?;
    let fault_evidence = fault_evidence_by_fact(root, contracts, universe.facts.keys())?;
    let producer_closures =
        producer_assurance::collect(root, workspace_facts, &universe.producers)?;

    let mut records = Vec::with_capacity(universe.producers.len() + universe.facts.len());
    for (id, contract) in &universe.producers {
        let spec = http_specs
            .get(id)
            .with_context(|| format!("generated producer disappeared: {id}"))?;
        validate_generated_producer(contract, spec)?;
        let emitted_facts = sorted_unique(
            &contract
                .manifest()
                .capabilities
                .outbox
                .as_ref()
                .context("validated producer missing outbox capability")?
                .emits,
            &format!("producer {id} emitted facts"),
        )?;
        let closure = producer_closures
            .get(id)
            .with_context(|| format!("active L2 producer lacks typed receipt closure: {id}"))?;
        let evidence = complete_producer_evidence(root, contract, closure)?;
        records.push(AssuranceRecord::producer(
            Identity::from_contract(contract),
            ProducerDetails { emitted_facts },
            evidence,
        ));
    }
    for (id, contract) in &universe.facts {
        let spec = event_specs
            .get(id)
            .with_context(|| format!("generated fact disappeared: {id}"))?;
        let subscriptions = validate_generated_fact(contract, spec)?;
        let fault = fault_evidence
            .get(id)
            .with_context(|| format!("active L2 fact lacks named fault evidence: {id}"))?;
        let evidence = complete_fact_evidence(
            root,
            contract,
            &subscriptions,
            named_fault_carriers(root, fault)?,
        )?;
        records.push(AssuranceRecord::fact(
            Identity::from_contract(contract),
            FactDetails {
                topic: contract
                    .manifest()
                    .topic
                    .clone()
                    .context("validated fact missing topic")?,
                subscriptions,
            },
            evidence,
        ));
    }
    records.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    Ok(Inventory {
        schema_version: 3,
        producer_count: universe.producers.len(),
        fact_count: universe.facts.len(),
        contracts: records,
    })
}

fn ensure_findings_empty<R: std::fmt::Debug>(
    label: &str,
    findings: &[crate::diagnostic::Finding<R>],
) -> Result<()> {
    if !findings.is_empty() {
        let details = findings
            .iter()
            .map(crate::diagnostic::format_finding)
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "{label} failed with {} finding(s):\n{details}",
            findings.len()
        );
    }
    Ok(())
}

struct L2Universe<'a> {
    producers: BTreeMap<String, &'a GovernedContract>,
    facts: BTreeMap<String, &'a GovernedContract>,
}

fn classify_active_l2(contracts: &[GovernedContract]) -> Result<L2Universe<'_>> {
    let mut producers = BTreeMap::new();
    let mut facts = BTreeMap::new();
    for discovered in contracts {
        let manifest = discovered.manifest();
        if manifest.lifecycle != Lifecycle::Active
            || manifest.consistency_level != ConsistencyLevel::OutboxFact
        {
            continue;
        }
        let role = manifest
            .capabilities
            .outbox
            .as_ref()
            .with_context(|| {
                format!(
                    "active OutboxFact contract {} lacks outbox role",
                    manifest.id
                )
            })?
            .role;
        match (manifest.kind, role) {
            (ContractKind::Http, OutboxRole::Producer) => {
                insert_unique(&mut producers, manifest.id.clone(), discovered, "producer")?;
            }
            (ContractKind::Event, OutboxRole::Fact) => {
                insert_unique(&mut facts, manifest.id.clone(), discovered, "fact")?;
            }
            (kind, role) => bail!(
                "active OutboxFact contract {} has forbidden kind/role pair {kind:?}/{role:?}",
                manifest.id
            ),
        }
    }
    let overlap = producers
        .keys()
        .filter(|id| facts.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        overlap.is_empty(),
        "contract ids occur in both L2 roles: {overlap:?}"
    );
    Ok(L2Universe { producers, facts })
}

fn insert_unique<'a>(
    map: &mut BTreeMap<String, &'a GovernedContract>,
    id: String,
    contract: &'a GovernedContract,
    role: &str,
) -> Result<()> {
    if map.insert(id.clone(), contract).is_some() {
        bail!("duplicate active L2 {role} contract id: {id}");
    }
    Ok(())
}

fn generated_http_specs() -> Result<BTreeMap<String, &'static generated::http::HttpSpec>> {
    let mut specs = BTreeMap::new();
    for spec in generated::http::SPECS {
        if spec.route.consistency_level() != HttpConsistencyLevel::OutboxFact {
            continue;
        }
        let id = spec.route.contract_id().to_string();
        if specs.insert(id.clone(), spec).is_some() {
            bail!("duplicate generated L2 HTTP spec: {id}");
        }
    }
    Ok(specs)
}

fn generated_event_specs() -> Result<BTreeMap<String, &'static generated::event::EventSpec>> {
    let mut specs = BTreeMap::new();
    for spec in generated::event::EVENTS {
        let id = spec.contract_id().to_string();
        if specs.insert(id.clone(), spec).is_some() {
            bail!("duplicate generated L2 event spec: {id}");
        }
    }
    Ok(specs)
}

fn validate_generated_producer(
    discovered: &GovernedContract,
    spec: &generated::http::HttpSpec,
) -> Result<()> {
    let manifest = discovered.manifest();
    let binding = spec.route.contract();
    ensure!(
        binding.contract_id() == manifest.id,
        "producer contract id drift"
    );
    ensure!(
        binding.domain() == manifest.domain,
        "producer domain drift: {}",
        manifest.id
    );
    ensure!(
        binding.version() == manifest.version,
        "producer version drift: {}",
        manifest.id
    );
    ensure!(
        binding.schema_hash() == discovered.schema_hash(),
        "producer schema hash drift: {}",
        manifest.id
    );
    let manifest_effects = manifest
        .effect_profile
        .as_ref()
        .with_context(|| format!("producer {} lacks effect profile", manifest.id))?
        .effects
        .iter()
        .map(|effect| effect.as_wire().to_string())
        .collect::<Vec<_>>();
    let generated_effects = spec
        .route
        .effect_profile()
        .effects()
        .iter()
        .map(|effect| generated_effect_wire(*effect).to_string())
        .collect::<Vec<_>>();
    ensure!(
        manifest_effects == generated_effects,
        "producer effect profile drift for {}: manifest={manifest_effects:?} generated={generated_effects:?}",
        manifest.id
    );
    let required = BTreeSet::from([
        EffectKind::BusinessWrite,
        EffectKind::BusinessTransaction,
        EffectKind::Outbox,
        EffectKind::Publish,
    ]);
    let actual = manifest
        .effect_profile
        .as_ref()
        .context("effect profile vanished")?
        .effects
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    ensure!(
        required.is_subset(&actual),
        "producer {} lacks required L2 effects",
        manifest.id
    );
    Ok(())
}

fn generated_effect_wire(effect: HttpEffectKind) -> &'static str {
    match effect {
        HttpEffectKind::Read => "read",
        HttpEffectKind::Auth => "auth",
        HttpEffectKind::Projection => "projection",
        HttpEffectKind::BusinessWrite => "business-write",
        HttpEffectKind::BusinessTransaction => "business-transaction",
        HttpEffectKind::Outbox => "outbox",
        HttpEffectKind::Publish => "publish",
        HttpEffectKind::Workflow => "workflow",
        HttpEffectKind::Saga => "saga",
        HttpEffectKind::Reconcile => "reconcile",
        HttpEffectKind::Worker => "worker",
        HttpEffectKind::CrossTenantAudit => "cross-tenant-audit",
    }
}

fn validate_generated_fact(
    discovered: &GovernedContract,
    spec: &generated::event::EventSpec,
) -> Result<Vec<SubscriptionIdentity>> {
    let manifest = discovered.manifest();
    let binding = spec.contract();
    ensure!(
        binding.contract_id() == manifest.id,
        "fact contract id drift"
    );
    ensure!(
        binding.domain() == manifest.domain,
        "fact domain drift: {}",
        manifest.id
    );
    ensure!(
        binding.version() == manifest.version,
        "fact version drift: {}",
        manifest.id
    );
    ensure!(
        binding.schema_hash() == discovered.schema_hash(),
        "fact schema hash drift: {}",
        manifest.id
    );
    ensure!(
        Some(spec.topic()) == manifest.topic.as_deref(),
        "fact topic drift: {}",
        manifest.id
    );
    let mut manifest_subscriptions = manifest
        .subscriptions
        .iter()
        .map(|subscription| SubscriptionValidation {
            consumer: subscription.consumer.clone(),
            group: subscription.group.clone(),
            execution: manifest_execution_wire(subscription.execution).to_string(),
            effect: subscription
                .effect
                .map(manifest_effect_wire)
                .map(str::to_string),
            external_effect_policy: manifest_external_effect_policy(
                subscription.external_effect_policy,
            ),
        })
        .collect::<Vec<_>>();
    manifest_subscriptions.sort();
    ensure_no_duplicate_subscriptions(&manifest.id, &manifest_subscriptions)?;
    let mut generated_subscriptions = spec
        .subscriptions()
        .iter()
        .map(|subscription| SubscriptionValidation {
            consumer: subscription.consumer().to_string(),
            group: subscription.group().to_string(),
            execution: generated_execution_wire(subscription.execution()).to_string(),
            effect: subscription
                .effect()
                .map(generated_subscription_effect_wire)
                .map(str::to_string),
            external_effect_policy: generated_external_effect_policy(
                subscription.external_effect_policy(),
            ),
        })
        .collect::<Vec<_>>();
    generated_subscriptions.sort();
    ensure_no_duplicate_subscriptions(&manifest.id, &generated_subscriptions)?;
    ensure!(
        manifest_subscriptions == generated_subscriptions,
        "fact subscription drift for {}: manifest={manifest_subscriptions:?} generated={generated_subscriptions:?}",
        manifest.id
    );
    Ok(manifest_subscriptions
        .into_iter()
        .map(|subscription| SubscriptionIdentity {
            consumer: subscription.consumer,
            group: subscription.group,
            external_effect_policy: subscription.external_effect_policy,
        })
        .collect())
}

fn ensure_no_duplicate_subscriptions(
    id: &str,
    subscriptions: &[SubscriptionValidation],
) -> Result<()> {
    for pair in subscriptions.windows(2) {
        ensure!(
            (pair[0].consumer.as_str(), pair[0].group.as_str())
                != (pair[1].consumer.as_str(), pair[1].group.as_str()),
            "duplicate subscription identity for {id}: {}/{}",
            pair[0].consumer,
            pair[0].group
        );
    }
    Ok(())
}

fn manifest_execution_wire(value: ManifestSubscriptionExecution) -> &'static str {
    match value {
        ManifestSubscriptionExecution::AdapterNative => "adapter-native",
        ManifestSubscriptionExecution::DomainEffect => "domain-effect",
    }
}

fn generated_execution_wire(value: GeneratedSubscriptionExecution) -> &'static str {
    match value {
        GeneratedSubscriptionExecution::AdapterNative => "adapter-native",
        GeneratedSubscriptionExecution::DomainEffect => "domain-effect",
    }
}

fn manifest_effect_wire(value: ManifestSubscriptionEffect) -> &'static str {
    match value {
        ManifestSubscriptionEffect::SettingsConfigVersionRefresh => {
            "settings-config-version-refresh"
        }
    }
}

fn generated_subscription_effect_wire(value: GeneratedSubscriptionEffect) -> &'static str {
    match value {
        GeneratedSubscriptionEffect::SettingsConfigVersionRefresh => {
            "settings-config-version-refresh"
        }
    }
}

fn manifest_external_effect_policy(
    value: ManifestExternalEffectPolicy,
) -> AssuranceExternalEffectPolicy {
    match value {
        ManifestExternalEffectPolicy::TransactionalOnly => {
            AssuranceExternalEffectPolicy::TransactionalOnly
        }
        ManifestExternalEffectPolicy::IdempotencyKey => {
            AssuranceExternalEffectPolicy::IdempotencyKey
        }
        ManifestExternalEffectPolicy::Reconcile => AssuranceExternalEffectPolicy::Reconcile,
        ManifestExternalEffectPolicy::Compensated => AssuranceExternalEffectPolicy::Compensated,
    }
}

fn generated_external_effect_policy(
    value: GeneratedExternalEffectPolicy,
) -> AssuranceExternalEffectPolicy {
    match value {
        GeneratedExternalEffectPolicy::TransactionalOnly => {
            AssuranceExternalEffectPolicy::TransactionalOnly
        }
        GeneratedExternalEffectPolicy::IdempotencyKey => {
            AssuranceExternalEffectPolicy::IdempotencyKey
        }
        GeneratedExternalEffectPolicy::Reconcile => AssuranceExternalEffectPolicy::Reconcile,
        GeneratedExternalEffectPolicy::Compensated => AssuranceExternalEffectPolicy::Compensated,
    }
}

type FaultEvidenceMap = BTreeMap<String, Vec<consistency_fixtures::ReadyL2FaultEvidence>>;

fn fault_evidence_by_fact<'a>(
    root: &Path,
    contracts: &[GovernedContract],
    fact_ids: impl Iterator<Item = &'a String>,
) -> Result<FaultEvidenceMap> {
    let expected = fact_ids.cloned().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut cases = BTreeSet::new();
    let mut by_fact: FaultEvidenceMap = BTreeMap::new();
    for evidence in consistency_fixtures::ready_l2_fault_evidence_from_validated(root, contracts)? {
        ensure!(
            expected.contains(&evidence.contract_id),
            "orphan ready L2 fault case {} targets {}",
            evidence.case_id,
            evidence.contract_id
        );
        ensure!(
            cases.insert(evidence.case_id.clone()),
            "duplicate ready L2 fault case id: {}",
            evidence.case_id
        );
        actual.insert(evidence.contract_id.clone());
        by_fact
            .entry(evidence.contract_id.clone())
            .or_default()
            .push(evidence);
    }
    ensure_exact_ids(
        "active L2 fact/fault evidence",
        expected.iter(),
        actual.iter(),
    )?;
    for evidence in by_fact.values_mut() {
        evidence.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    }
    Ok(by_fact)
}

struct FactEvidence;

fn complete_producer_evidence(
    root: &Path,
    contract: &GovernedContract,
    execution: &producer_assurance::ProducerExecutionProjection,
) -> Result<CompleteProducerEvidence> {
    let manifest_path = repo_label(root, contract.manifest_path())?;
    let generated = crate::codegen::GeneratedCarrier::from_contract(contract)?;
    let spec = generated.item(crate::codegen::GeneratedItem::Spec)?;
    let producer = generated.item(crate::codegen::GeneratedItem::Producer)?;
    let route = Carrier::new(
        root,
        CarrierKind::RustSymbol,
        &execution.route.repo_path,
        &execution.route.symbol,
    )?;
    let mounted_handler = Carrier::new(
        root,
        CarrierKind::RustSymbol,
        &execution.mounted_handler.repo_path,
        &execution.mounted_handler.symbol,
    )?;
    let terminals = execution
        .terminals
        .iter()
        .map(|terminal| {
            let domain_path = terminal
                .domain_path
                .iter()
                .map(|item| {
                    Carrier::new(root, CarrierKind::RustSymbol, &item.repo_path, &item.symbol)
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !domain_path.is_empty(),
                "producer terminal {} has empty domain execution path",
                terminal.fact_id
            );
            Ok(ProducerTerminalEvidence {
                fact_id: terminal.fact_id.clone(),
                domain_path,
                port_method: Carrier::new(
                    root,
                    CarrierKind::RustSymbol,
                    &terminal.port_method.repo_path,
                    &terminal.port_method.symbol,
                )?,
                provider_method: Carrier::new(
                    root,
                    CarrierKind::RustSymbol,
                    &terminal.provider_method.repo_path,
                    &terminal.provider_method.symbol,
                )?,
                production_composition: ProductionCompositionEvidence {
                    runtime_entry: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.production_composition.runtime_entry_path,
                        &terminal.production_composition.runtime_entry,
                    )?,
                    runtime_assembly: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.production_composition.runtime_assembly_path,
                        &terminal.production_composition.runtime_assembly,
                    )?,
                    runtime_module: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.production_composition.runtime_module_path,
                        &terminal.production_composition.runtime_module,
                    )?,
                    wire: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.production_composition.repo_path,
                        &terminal.production_composition.wire,
                    )?,
                    service_constructor: terminal
                        .production_composition
                        .service_constructor
                        .clone(),
                    provider_factory: terminal.production_composition.provider_factory.clone(),
                },
                transaction: Carrier::new(
                    root,
                    CarrierKind::RustSymbol,
                    &terminal.transaction.repo_path,
                    &terminal.transaction.symbol,
                )?,
                capability: Carrier::new(
                    root,
                    CarrierKind::RustType,
                    &terminal.capability.repo_path,
                    &terminal.capability.symbol,
                )?,
                append: Carrier::new(
                    root,
                    CarrierKind::RustSymbol,
                    &terminal.append.repo_path,
                    &terminal.append.symbol,
                )?,
                settlement: Carrier::new(
                    root,
                    CarrierKind::RustSymbol,
                    &terminal.settlement.repo_path,
                    &terminal.settlement.symbol,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !terminals.is_empty(),
        "producer {} has no execution terminals",
        contract.manifest().id
    );
    let fault = ProducerFaultEvidence::new(
        execution
            .terminals
            .iter()
            .map(|terminal| {
                Ok(ProducerFaultTerminalEvidence {
                    fact_id: terminal.fact_id.clone(),
                    provider_method: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.provider_method.repo_path,
                        &terminal.provider_method.symbol,
                    )?,
                    transaction: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.transaction.repo_path,
                        &terminal.transaction.symbol,
                    )?,
                    rollback: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.rollback.repo_path,
                        &terminal.rollback.symbol,
                    )?,
                    commit_unknown: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.commit_unknown.repo_path,
                        &terminal.commit_unknown.symbol,
                    )?,
                    rollback_failed: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.rollback_failed.repo_path,
                        &terminal.rollback_failed.symbol,
                    )?,
                    no_replay: Carrier::new(
                        root,
                        CarrierKind::RustSymbol,
                        &terminal.no_replay.repo_path,
                        &terminal.no_replay.symbol,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    Ok(CompleteProducerEvidence::new(
        EvidenceFacet::new(vec![Carrier::new(
            root,
            CarrierKind::Manifest,
            &manifest_path,
            "id",
        )?])?,
        EvidenceFacet::new(vec![
            Carrier::new(root, CarrierKind::RustSymbol, &spec.repo_path, &spec.symbol)?,
            Carrier::new(
                root,
                CarrierKind::RustSymbol,
                &producer.repo_path,
                &producer.symbol,
            )?,
        ])?,
        ProducerExecutionEvidence {
            status: EvidenceStatus::Complete,
            route,
            mounted_handler,
            terminals,
        },
        fault,
    ))
}

fn complete_fact_evidence(
    root: &Path,
    contract: &GovernedContract,
    subscriptions: &[SubscriptionIdentity],
    fault_carriers: Vec<Carrier>,
) -> Result<CompleteEvidence<FactEvidence>> {
    let manifest_path = repo_label(root, contract.manifest_path())?;
    let generated = crate::codegen::GeneratedCarrier::from_contract(contract)?;
    let spec = generated.item(crate::codegen::GeneratedItem::Spec)?;
    let runtime = ["bridge_generated_subscriptions", "resolve_parts"]
        .iter()
        .map(|symbol| {
            Carrier::new(
                root,
                CarrierKind::RustSymbol,
                "composition/eventing/src/lib.rs",
                symbol,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    CompleteEvidence::new(
        EvidenceFacet::new(vec![Carrier::new(
            root,
            CarrierKind::Manifest,
            &manifest_path,
            "id",
        )?])?,
        EvidenceFacet::new(vec![Carrier::new(
            root,
            CarrierKind::RustSymbol,
            &spec.repo_path,
            &spec.symbol,
        )?])?,
        EvidenceFacet::new(runtime)?,
        EvidenceFacet::new(fact_effect_policy_carriers(root, subscriptions)?)?,
        EvidenceFacet::new(fault_carriers)?,
    )
}

fn fact_effect_policy_carriers(
    root: &Path,
    subscriptions: &[SubscriptionIdentity],
) -> Result<Vec<Carrier>> {
    verify_policy_edge(
        root,
        "policy executor",
        "composition/eventing/src/lib.rs",
        "worker_spec",
        PolicyCallRequirement::exact("spawn_consumer_ackable_tx_subscriber", ["", ""]),
    )?;
    let mut carriers = Vec::new();
    for subscription in subscriptions {
        let spec = subscription_policy_chain(subscription)?;
        if let Some(entrypoint) = spec.registration_entrypoint {
            verify_policy_symbol(root, "registration entrypoint", entrypoint)?;
        }
        carriers.push(discover_policy_carrier(
            root,
            "registration",
            spec.registration,
        )?);
        verify_runtime_policy_route(root, spec.route)?;
        carriers.push(discover_policy_carrier(root, "handler", spec.handler)?);
    }
    carriers.push(Carrier::new(
        root,
        CarrierKind::RustSymbol,
        "composition/eventing/src/lib.rs",
        "resolve_parts",
    )?);
    carriers.push(Carrier::new(
        root,
        CarrierKind::RustSymbol,
        "composition/eventing/src/consumer_tx.rs",
        "spawn_consumer_ackable_tx_subscriber",
    )?);
    carriers.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    carriers.dedup();
    Ok(carriers)
}

#[derive(Clone, Copy)]
struct PolicySymbolSpec {
    repo_path: &'static str,
    symbol: &'static str,
    required_trait: Option<&'static str>,
    required_call: Option<PolicyCallRequirement>,
}

#[derive(Clone, Copy)]
enum PolicyCalleeMatch {
    Exact,
    Prefix,
    Suffix,
}

#[derive(Clone, Copy)]
struct PolicyCallRequirement {
    callee: &'static str,
    callee_match: PolicyCalleeMatch,
    required_args: [&'static str; 2],
}

impl PolicyCallRequirement {
    const fn exact(callee: &'static str, required_args: [&'static str; 2]) -> Self {
        Self {
            callee,
            callee_match: PolicyCalleeMatch::Exact,
            required_args,
        }
    }

    const fn prefix(callee: &'static str) -> Self {
        Self {
            callee,
            callee_match: PolicyCalleeMatch::Prefix,
            required_args: ["", ""],
        }
    }

    const fn suffix(callee: &'static str) -> Self {
        Self {
            callee,
            callee_match: PolicyCalleeMatch::Suffix,
            required_args: ["", ""],
        }
    }

    fn matches(self, call: &ReachableCall) -> bool {
        let callee_matches = match self.callee_match {
            PolicyCalleeMatch::Exact => call.callee == self.callee,
            PolicyCalleeMatch::Prefix => call.callee.starts_with(self.callee),
            PolicyCalleeMatch::Suffix => call.callee.ends_with(self.callee),
        };
        callee_matches
            && self
                .required_args
                .into_iter()
                .filter(|required| !required.is_empty())
                .all(|required| call.args.iter().any(|argument| argument == required))
    }
}

#[derive(Clone, Copy)]
struct SubscriptionPolicyChain {
    registration_entrypoint: Option<PolicySymbolSpec>,
    registration: PolicySymbolSpec,
    route: PolicyRouteSpec,
    handler: PolicySymbolSpec,
}

#[derive(Clone, Copy)]
struct PolicyRouteSpec {
    dispatch_pattern: &'static str,
    plan_pattern: &'static str,
    worker_symbol: &'static str,
    resolver_call: PolicyCallRequirement,
    handler_call: PolicyCallRequirement,
    worker_call: PolicyCallRequirement,
}

impl PolicyRouteSpec {
    const fn audit(
        dispatch_pattern: &'static str,
        plan_pattern: &'static str,
        handler_constructor: &'static str,
    ) -> Self {
        Self {
            dispatch_pattern,
            plan_pattern,
            worker_symbol: "AuditConsumerFactory::worker",
            resolver_call: PolicyCallRequirement::exact("require_adapter_native", ["", ""]),
            handler_call: PolicyCallRequirement::suffix(handler_constructor),
            worker_call: PolicyCallRequirement::prefix("worker_spec::<policy::TransactionalOnly,"),
        }
    }

    const fn settings() -> Self {
        Self {
            dispatch_pattern: "SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings",
            plan_pattern: "DispatchPlan::ConfigVersionChanged(effect)",
            worker_symbol: "SettingsConsumerFactory::worker",
            resolver_call: PolicyCallRequirement::exact("require_settings_reconcile", ["", ""]),
            handler_call: PolicyCallRequirement::suffix(".config_version_changed_consumer_tx"),
            worker_call: PolicyCallRequirement::prefix("worker_spec::<policy::Reconcile,"),
        }
    }
}

fn subscription_policy_chain(
    subscription: &SubscriptionIdentity,
) -> Result<SubscriptionPolicyChain> {
    let chain = match (
        subscription.consumer.as_str(),
        subscription.group.as_str(),
        subscription.external_effect_policy,
    ) {
        ("audit", "audit.session-created", AssuranceExternalEffectPolicy::TransactionalOnly) => {
            audit_policy_chain(
                "generated::event::identity_v1::session_created::subscribe_audit",
                PolicyRouteSpec::audit(
                    "SubscriptionDispatchKey::IdentitySessionCreatedV1Audit",
                    "DispatchPlan::SessionCreated",
                    ".session_created_consumer_tx",
                ),
            )
        }
        ("audit", "audit.role-assigned", AssuranceExternalEffectPolicy::TransactionalOnly) => {
            audit_policy_chain(
                "generated::event::identity_v1::role_assigned::subscribe_audit",
                PolicyRouteSpec::audit(
                    "SubscriptionDispatchKey::IdentityRoleAssignedV1Audit",
                    "DispatchPlan::RoleAssigned",
                    ".role_assigned_consumer_tx",
                ),
            )
        }
        ("audit", "audit.role-revoked", AssuranceExternalEffectPolicy::TransactionalOnly) => {
            audit_policy_chain(
                "generated::event::identity_v1::role_revoked::subscribe_audit",
                PolicyRouteSpec::audit(
                    "SubscriptionDispatchKey::IdentityRoleRevokedV1Audit",
                    "DispatchPlan::RoleRevoked",
                    ".role_revoked_consumer_tx",
                ),
            )
        }
        ("audit", "audit.policy-updated", AssuranceExternalEffectPolicy::TransactionalOnly) => {
            audit_policy_chain(
                "generated::event::identity_v1::policy_updated::subscribe_audit",
                PolicyRouteSpec::audit(
                    "SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit",
                    "DispatchPlan::PolicyUpdated",
                    ".policy_updated_consumer_tx",
                ),
            )
        }
        ("audit", "audit.security-event", AssuranceExternalEffectPolicy::TransactionalOnly) => {
            audit_policy_chain(
                "generated::event::identity_v1::security_event::subscribe_audit",
                PolicyRouteSpec::audit(
                    "SubscriptionDispatchKey::IdentitySecurityEventV1Audit",
                    "DispatchPlan::SecurityEvent",
                    ".security_event_consumer_tx",
                ),
            )
        }
        (
            "settings",
            "settings.config-version-changed",
            AssuranceExternalEffectPolicy::Reconcile,
        ) => settings_policy_chain(),
        _ => {
            bail!(
                "active subscription {}/{} with policy {:?} has no closed production policy chain",
                subscription.consumer,
                subscription.group,
                subscription.external_effect_policy
            )
        }
    };
    Ok(chain)
}

const fn audit_policy_chain(
    registration_wrapper: &'static str,
    route: PolicyRouteSpec,
) -> SubscriptionPolicyChain {
    SubscriptionPolicyChain {
        registration_entrypoint: Some(PolicySymbolSpec {
            repo_path: "crates/audit/src/application.rs",
            symbol: "AuditDomain::init",
            required_trait: None,
            required_call: Some(PolicyCallRequirement::exact(
                "register_audit_subscriber",
                ["reg", ""],
            )),
        }),
        registration: PolicySymbolSpec {
            repo_path: "crates/audit/src/application.rs",
            symbol: "register_audit_subscriber",
            required_trait: None,
            required_call: Some(PolicyCallRequirement::exact(
                registration_wrapper,
                ["reg", "SubscriberCapability::AdapterNativeTransactional"],
            )),
        },
        route,
        handler: PolicySymbolSpec {
            repo_path: "composition/eventing/src/consumer_tx.rs",
            symbol: "PgAuditConsumerTx::handle",
            required_trait: Some("ConsumerTxHandler<policy::TransactionalOnly>"),
            required_call: Some(PolicyCallRequirement::exact(
                "postgres::PgAuditConsumerTx::handle",
                ["", ""],
            )),
        },
    }
}

const fn settings_policy_chain() -> SubscriptionPolicyChain {
    SubscriptionPolicyChain {
        registration_entrypoint: None,
        registration: PolicySymbolSpec {
            repo_path: "crates/settings/src/application.rs",
            symbol: "SettingsDomain::init",
            required_trait: None,
            required_call: Some(PolicyCallRequirement::exact(
                "version_changed::subscribe_settings",
                ["reg", "SubscriberCapability::DomainReconcile(effect)"],
            )),
        },
        route: PolicyRouteSpec::settings(),
        handler: PolicySymbolSpec {
            repo_path: "composition/eventing/src/consumer_tx.rs",
            symbol: "PgSettingsConsumerTx::handle",
            required_trait: Some("ConsumerTxHandler<policy::Reconcile>"),
            required_call: Some(PolicyCallRequirement::exact(
                "postgres::PgSettingsConsumerTx::handle",
                ["", ""],
            )),
        },
    }
}

fn verify_runtime_policy_route(root: &Path, route: PolicyRouteSpec) -> Result<()> {
    verify_policy_match_arm(
        root,
        "policy plan dispatch",
        "composition/eventing/src/lib.rs",
        "resolve_parts",
        "dispatch",
        route.dispatch_pattern,
        &[route.resolver_call],
    )?;
    verify_policy_match_arm(
        root,
        "policy worker selection",
        "composition/eventing/src/lib.rs",
        route.worker_symbol,
        "token.plan",
        route.plan_pattern,
        &[route.handler_call, route.worker_call],
    )?;
    Ok(())
}

fn verify_policy_match_arm(
    root: &Path,
    stage: &str,
    repo_path: &str,
    symbol: &str,
    match_input: &str,
    arm_pattern: &str,
    required_calls: &[PolicyCallRequirement],
) -> Result<()> {
    let source = generated_file::read_stable_utf8_file(
        &root.join(repo_path),
        MAX_RUST_CARRIER_BYTES,
        "ConsumerTx policy carrier",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("cannot parse ConsumerTx policy carrier {repo_path}"))?;
    let blocks = exact_policy_symbol_blocks(&syntax.items, symbol);
    ensure!(
        blocks.len() == 1,
        "ConsumerTx {stage} must resolve exact production carrier {repo_path}::{symbol} once, got {}",
        blocks.len()
    );
    let matches = blocks[0]
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let expression = match statement {
                syn::Stmt::Expr(syn::Expr::Match(expression), _) => expression,
                syn::Stmt::Local(local) => {
                    let initializer = local.init.as_ref()?;
                    let syn::Expr::Match(expression) = initializer.expr.as_ref() else {
                        return None;
                    };
                    expression
                }
                _ => return None,
            };
            (policy_tokens(&expression.expr) == match_input).then_some(expression)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "ConsumerTx {stage} carrier {repo_path}::{symbol} must match exact input `{match_input}` once, got {}",
        matches.len()
    );
    let arms = matches[0]
        .arms
        .iter()
        .filter(|arm| policy_tokens(&arm.pat) == arm_pattern)
        .collect::<Vec<_>>();
    ensure!(
        arms.len() == 1 && arms[0].guard.is_none(),
        "ConsumerTx {stage} carrier {repo_path}::{symbol} must contain one unguarded `{arm_pattern}` arm"
    );
    let calls = reachable_calls_in_expr(&arms[0].body);
    for required in required_calls {
        ensure!(
            calls.iter().any(|call| required.matches(call)),
            "ConsumerTx {stage} arm `{arm_pattern}` is outside the closed execution chain: missing reachable call `{}`",
            required.callee
        );
    }
    Ok(())
}

fn verify_policy_edge(
    root: &Path,
    stage: &str,
    repo_path: &str,
    function_name: &str,
    required_call: PolicyCallRequirement,
) -> Result<()> {
    let source = generated_file::read_stable_utf8_file(
        &root.join(repo_path),
        MAX_RUST_CARRIER_BYTES,
        "ConsumerTx policy carrier",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("cannot parse ConsumerTx policy carrier {repo_path}"))?;
    verify_policy_call_edge_in_syntax(&syntax, stage, repo_path, function_name, required_call)
}

fn verify_policy_call_edge_in_syntax(
    syntax: &syn::File,
    stage: &str,
    repo_path: &str,
    function_name: &str,
    required_call: PolicyCallRequirement,
) -> Result<()> {
    let functions = syntax
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            (function.sig.ident == function_name && !attrs_are_conditional(&function.attrs))
                .then_some(function)
        })
        .collect::<Vec<_>>();
    ensure!(
        functions.len() == 1,
        "ConsumerTx {stage} must resolve exact production carrier {repo_path}::{function_name} once, got {}",
        functions.len()
    );
    let calls = reachable_consumer_tx_calls_in_block(&functions[0].block);
    ensure!(
        calls.iter().any(|call| required_call.matches(call)),
        "ConsumerTx {stage} carrier {repo_path}::{function_name} is outside the closed execution chain: missing reachable call `{}`",
        required_call.callee
    );
    Ok(())
}

fn discover_policy_carrier(root: &Path, stage: &str, spec: PolicySymbolSpec) -> Result<Carrier> {
    verify_policy_symbol(root, stage, spec)?;
    Carrier::new(root, CarrierKind::RustSymbol, spec.repo_path, spec.symbol)
}

fn verify_policy_symbol(root: &Path, stage: &str, spec: PolicySymbolSpec) -> Result<()> {
    let source_path = root.join(spec.repo_path);
    let source = generated_file::read_stable_utf8_file(
        &source_path,
        MAX_RUST_CARRIER_BYTES,
        "ConsumerTx policy carrier",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("cannot parse ConsumerTx policy carrier {}", spec.repo_path))?;
    verify_policy_symbol_in_syntax(&syntax, stage, spec)
}

fn verify_policy_symbol_in_syntax(
    syntax: &syn::File,
    stage: &str,
    spec: PolicySymbolSpec,
) -> Result<()> {
    let matches = exact_policy_symbol_evidence(&syntax.items, spec.symbol);
    ensure!(
        matches.len() == 1,
        "ConsumerTx {stage} must resolve exact production carrier {}::{} once, got {}",
        spec.repo_path,
        spec.symbol,
        matches.len()
    );
    let evidence = &matches[0];
    if let Some(required_trait) = spec.required_trait {
        ensure!(
            evidence.trait_path.as_deref() == Some(required_trait),
            "ConsumerTx {stage} carrier {}::{} is outside the closed execution chain: missing exact trait `{required_trait}`",
            spec.repo_path,
            spec.symbol
        );
    }
    if let Some(required_call) = spec.required_call {
        ensure!(
            evidence
                .calls
                .iter()
                .any(|call| required_call.matches(call)),
            "ConsumerTx {stage} carrier {}::{} is outside the closed execution chain: missing reachable call `{}`",
            spec.repo_path,
            spec.symbol,
            required_call.callee
        );
    }
    Ok(())
}

struct PolicySymbolEvidence {
    trait_path: Option<String>,
    calls: Vec<ReachableCall>,
}

struct PolicySymbolBlock<'a> {
    block: &'a syn::Block,
}

fn exact_policy_symbol_blocks<'a>(
    items: &'a [syn::Item],
    symbol: &str,
) -> Vec<PolicySymbolBlock<'a>> {
    let segments = symbol.split("::").collect::<Vec<_>>();
    let mut matches = Vec::new();
    for item in items {
        match (segments.as_slice(), item) {
            ([function], syn::Item::Fn(item))
                if item.sig.ident == *function && !attrs_are_conditional(&item.attrs) =>
            {
                matches.push(PolicySymbolBlock { block: &item.block });
            }
            ([owner, method], syn::Item::Impl(item))
                if !attrs_are_conditional(&item.attrs)
                    && type_last_ident(&item.self_ty).as_deref() == Some(*owner) =>
            {
                for impl_item in &item.items {
                    let syn::ImplItem::Fn(function) = impl_item else {
                        continue;
                    };
                    if function.sig.ident == *method && !attrs_are_conditional(&function.attrs) {
                        matches.push(PolicySymbolBlock {
                            block: &function.block,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    matches
}

fn exact_policy_symbol_evidence(items: &[syn::Item], symbol: &str) -> Vec<PolicySymbolEvidence> {
    let segments = symbol.split("::").collect::<Vec<_>>();
    let mut matches = Vec::new();
    for item in items {
        match (segments.as_slice(), item) {
            ([function], syn::Item::Fn(item))
                if item.sig.ident == *function && !attrs_are_conditional(&item.attrs) =>
            {
                matches.push(PolicySymbolEvidence {
                    trait_path: None,
                    calls: reachable_calls_in_block(&item.block),
                });
            }
            ([owner, method], syn::Item::Impl(item))
                if !attrs_are_conditional(&item.attrs)
                    && type_last_ident(&item.self_ty).as_deref() == Some(*owner) =>
            {
                let trait_tokens = item
                    .trait_
                    .as_ref()
                    .map_or_else(String::new, |(_, path, _)| policy_tokens(path));
                for impl_item in &item.items {
                    let syn::ImplItem::Fn(function) = impl_item else {
                        continue;
                    };
                    if function.sig.ident == *method && !attrs_are_conditional(&function.attrs) {
                        matches.push(PolicySymbolEvidence {
                            trait_path: (!trait_tokens.is_empty()).then_some(trait_tokens.clone()),
                            calls: reachable_calls_in_block(&function.block),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    matches
}

struct ReachableCall {
    callee: String,
    args: Vec<String>,
}

#[derive(Default)]
struct ReachableCallVisitor {
    calls: Vec<ReachableCall>,
}

impl<'ast> Visit<'ast> for ReachableCallVisitor {
    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if matches!(statement, syn::Stmt::Item(_)) {
            return;
        }
        syn::visit::visit_stmt(self, statement);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.calls.push(ReachableCall {
            callee: policy_tokens(&call.func),
            args: call.args.iter().map(policy_tokens).collect(),
        });
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(ReachableCall {
            callee: format!(
                "{}.{}",
                policy_tokens(&call.receiver),
                policy_tokens(&call.method)
            ),
            args: call.args.iter().map(policy_tokens).collect(),
        });
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        match bool_literal(&expression.cond) {
            Some(true) => self.visit_block(&expression.then_branch),
            Some(false) => {
                if let Some((_, otherwise)) = &expression.else_branch {
                    self.visit_expr(otherwise);
                }
            }
            None => syn::visit::visit_expr_if(self, expression),
        }
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        if bool_literal(&expression.cond) != Some(false) {
            syn::visit::visit_expr_while(self, expression);
        }
    }

    fn visit_expr_closure(&mut self, _closure: &'ast syn::ExprClosure) {}
}

fn bool_literal(expression: &syn::Expr) -> Option<bool> {
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Bool(value),
        ..
    }) = expression
    else {
        return None;
    };
    Some(value.value)
}

fn reachable_calls_in_block(block: &syn::Block) -> Vec<ReachableCall> {
    let mut visitor = ReachableCallVisitor::default();
    visitor.visit_block(block);
    if let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() {
        visit_returned_sanctioned_closure(tail, &mut visitor, ReturnedClosureLane::BoxOnly);
    }
    visitor.calls
}

fn reachable_consumer_tx_calls_in_block(block: &syn::Block) -> Vec<ReachableCall> {
    let mut visitor = ReachableCallVisitor::default();
    if let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() {
        visit_returned_sanctioned_closure(tail, &mut visitor, ReturnedClosureLane::ConsumerTx);
    }
    visitor.calls
}

fn reachable_calls_in_expr(expression: &syn::Expr) -> Vec<ReachableCall> {
    let mut visitor = ReachableCallVisitor::default();
    visitor.visit_expr(expression);
    visitor.calls
}

#[derive(Clone, Copy)]
enum ReturnedClosureLane {
    BoxOnly,
    ConsumerTx,
}

fn visit_returned_sanctioned_closure(
    expression: &syn::Expr,
    visitor: &mut ReachableCallVisitor,
    lane: ReturnedClosureLane,
) {
    let syn::Expr::Call(call) = expression else {
        return;
    };
    let constructor = policy_tokens(&call.func);
    if constructor != "Box::new"
        && !(matches!(lane, ReturnedClosureLane::ConsumerTx)
            && constructor == "WorkerSpec::consumer_deferred")
    {
        return;
    }
    for argument in &call.args {
        if let syn::Expr::Closure(closure) = argument {
            visitor.visit_expr(&closure.body);
        }
    }
}

fn policy_tokens(tokens: &impl quote::ToTokens) -> String {
    quote::ToTokens::to_token_stream(tokens)
        .to_string()
        .replace(' ', "")
}

fn named_fault_carriers(
    root: &Path,
    evidence: &[consistency_fixtures::ReadyL2FaultEvidence],
) -> Result<Vec<Carrier>> {
    let mut carriers = Vec::new();
    for item in evidence {
        carriers.push(Carrier::new(
            root,
            CarrierKind::FaultFixture,
            &item.fixture_carrier,
            &item.case_id,
        )?);
        carriers.push(Carrier::new(
            root,
            CarrierKind::RustSymbol,
            &item.runner_carrier,
            &item.runner_symbol,
        )?);
    }
    Ok(carriers)
}

fn sorted_unique(values: &[String], label: &str) -> Result<Vec<String>> {
    let mut sorted = values.to_vec();
    sorted.sort();
    for pair in sorted.windows(2) {
        ensure!(pair[0] != pair[1], "{label} contains duplicate {}", pair[0]);
    }
    Ok(sorted)
}

fn ensure_exact_ids<'a>(
    label: &str,
    expected: impl Iterator<Item = &'a String>,
    actual: impl Iterator<Item = &'a String>,
) -> Result<()> {
    let expected = collect_unique_ids(label, "expected", expected)?;
    let actual = collect_unique_ids(label, "actual", actual)?;
    ensure!(
        expected == actual,
        "{label} identity mismatch: missing={:?} extra={:?}",
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(&expected).collect::<Vec<_>>()
    );
    Ok(())
}

fn collect_unique_ids<'a>(
    label: &str,
    side: &str,
    values: impl Iterator<Item = &'a String>,
) -> Result<BTreeSet<String>> {
    let mut identities = BTreeSet::new();
    for identity in values {
        ensure!(
            identities.insert(identity.clone()),
            "{label} {side} contains duplicate identity {identity}"
        );
    }
    Ok(identities)
}

fn repo_label(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("path escapes workspace: {}", path.display()))?;
    let value = relative
        .to_str()
        .context("repository carrier path is not UTF-8")?;
    validate_repo_relative_path(root, value)?;
    Ok(value.to_string())
}

fn validate_repo_relative_path(root: &Path, value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "repository carrier path is empty");
    ensure!(
        !value.contains('\\'),
        "repository carrier path contains backslash"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "repository carrier path contains control character"
    );
    let path = Path::new(value);
    ensure!(!path.is_absolute(), "repository carrier path is absolute");
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_))),
        "repository carrier path is not canonical"
    );
    let mut current = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(part) = component else {
            bail!("validated carrier path retained a non-normal component")
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("carrier does not exist: {value}"))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "carrier path traverses symlink: {value}"
        );
    }
    ensure!(current.is_file(), "carrier is not a regular file: {value}");
    Ok(())
}

fn validate_output_path(root: &Path, output: &Path) -> Result<()> {
    ensure!(
        output == root.join(OUTPUT),
        "L2 assurance output path is fixed"
    );
    let parent = output
        .parent()
        .context("L2 assurance output lacks parent")?;
    let relative = parent
        .strip_prefix(root)
        .context("L2 assurance output parent escapes workspace")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            bail!("L2 assurance output parent is not canonical")
        };
        current.push(part);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect output parent: {}", current.display()));
            }
        };
        ensure!(metadata.is_dir(), "output parent is not a real directory");
        ensure!(
            !metadata.file_type().is_symlink(),
            "output parent traverses symlink"
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(output) {
        ensure!(
            metadata.is_file(),
            "L2 assurance output is not a regular file"
        );
        ensure!(
            !metadata.file_type().is_symlink(),
            "L2 assurance output is a symlink"
        );
    }
    Ok(())
}

fn render(inventory: &Inventory) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(inventory)?;
    ensure!(!bytes.contains(&b'\r'), "rendered assurance contains CR");
    while bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn check_rendered_file(path: &Path, expected: &[u8]) -> Result<()> {
    check_rendered_file_with_hook(path, expected, || {})
}

fn check_rendered_file_with_hook(
    path: &Path,
    expected: &[u8],
    after_open: impl FnOnce(),
) -> Result<()> {
    let max_bytes = u64::try_from(expected.len()).context("expected assurance bytes exceed u64")?;
    let actual = generated_file::read_stable_utf8_file_with_hook(
        path,
        max_bytes,
        "L2 assurance committed artifact",
        after_open,
    )
    .with_context(|| {
        format!(
            "cannot read {}; run `./hack/cargo.sh xtask l2-assurance`",
            path.display()
        )
    })?
    .into_bytes();
    ensure!(
        actual == expected,
        "{} drifted; run `./hack/cargo.sh xtask l2-assurance`",
        path.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Inventory {
    schema_version: u8,
    producer_count: usize,
    fact_count: usize,
    contracts: Vec<AssuranceRecord>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum AssuranceRecord {
    Producer(ProducerRecord),
    Fact(FactRecord),
}

impl AssuranceRecord {
    fn producer(
        identity: Identity,
        details: ProducerDetails,
        evidence: CompleteProducerEvidence,
    ) -> Self {
        Self::Producer(ProducerRecord {
            contract_id: identity.contract_id,
            domain: identity.domain,
            version: identity.version,
            role: Role::Producer,
            status: ClosedStatus::Closed,
            emitted_facts: details.emitted_facts,
            evidence: evidence.into_wire(),
        })
    }

    fn fact(
        identity: Identity,
        details: FactDetails,
        evidence: CompleteEvidence<FactEvidence>,
    ) -> Self {
        Self::Fact(FactRecord {
            contract_id: identity.contract_id,
            domain: identity.domain,
            version: identity.version,
            role: Role::Fact,
            status: ClosedStatus::Closed,
            topic: details.topic,
            subscriptions: details.subscriptions,
            evidence: evidence.into_wire(),
        })
    }

    fn sort_key(&self) -> (&str, Role) {
        match self {
            Self::Producer(record) => (&record.contract_id, record.role),
            Self::Fact(record) => (&record.contract_id, record.role),
        }
    }
}

#[derive(Debug)]
struct Identity {
    contract_id: String,
    domain: String,
    version: String,
}

impl Identity {
    fn from_contract(contract: &GovernedContract) -> Self {
        Self {
            contract_id: contract.manifest().id.clone(),
            domain: contract.manifest().domain.clone(),
            version: contract.manifest().version.clone(),
        }
    }
}

#[derive(Debug)]
struct ProducerDetails {
    emitted_facts: Vec<String>,
}

#[derive(Debug)]
struct FactDetails {
    topic: String,
    subscriptions: Vec<SubscriptionIdentity>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProducerRecord {
    contract_id: String,
    domain: String,
    version: String,
    role: Role,
    status: ClosedStatus,
    emitted_facts: Vec<String>,
    evidence: ProducerEvidenceWire,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FactRecord {
    contract_id: String,
    domain: String,
    version: String,
    role: Role,
    status: ClosedStatus,
    topic: String,
    subscriptions: Vec<SubscriptionIdentity>,
    evidence: EvidenceWire,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionIdentity {
    consumer: String,
    group: String,
    external_effect_policy: AssuranceExternalEffectPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SubscriptionValidation {
    consumer: String,
    group: String,
    execution: String,
    effect: Option<String>,
    external_effect_policy: AssuranceExternalEffectPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AssuranceExternalEffectPolicy {
    TransactionalOnly,
    IdempotencyKey,
    Reconcile,
    Compensated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Producer,
    Fact,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ClosedStatus {
    Closed,
}

struct CompleteEvidence<R> {
    contract: EvidenceFacet,
    generated: EvidenceFacet,
    runtime: EvidenceFacet,
    effect: EvidenceFacet,
    fault: EvidenceFacet,
    role: PhantomData<fn() -> R>,
}

struct CompleteProducerEvidence {
    contract: EvidenceFacet,
    generated: EvidenceFacet,
    execution: ProducerExecutionEvidence,
    fault: ProducerFaultEvidence,
}

impl CompleteProducerEvidence {
    fn new(
        contract: EvidenceFacet,
        generated: EvidenceFacet,
        execution: ProducerExecutionEvidence,
        fault: ProducerFaultEvidence,
    ) -> Self {
        Self {
            contract,
            generated,
            execution,
            fault,
        }
    }

    fn into_wire(self) -> ProducerEvidenceWire {
        ProducerEvidenceWire {
            contract: self.contract,
            generated: self.generated,
            execution: self.execution,
            fault: self.fault,
        }
    }
}

impl<R> CompleteEvidence<R> {
    fn new(
        contract: EvidenceFacet,
        generated: EvidenceFacet,
        runtime: EvidenceFacet,
        effect: EvidenceFacet,
        fault: EvidenceFacet,
    ) -> Result<Self> {
        Ok(Self {
            contract,
            generated,
            runtime,
            effect,
            fault,
            role: PhantomData,
        })
    }

    fn into_wire(self) -> EvidenceWire {
        EvidenceWire {
            contract: self.contract,
            generated: self.generated,
            runtime: self.runtime,
            effect: self.effect,
            fault: self.fault,
        }
    }
}

#[derive(Debug, Serialize)]
struct EvidenceWire {
    contract: EvidenceFacet,
    generated: EvidenceFacet,
    runtime: EvidenceFacet,
    effect: EvidenceFacet,
    fault: EvidenceFacet,
}

#[derive(Debug, Serialize)]
struct ProducerEvidenceWire {
    contract: EvidenceFacet,
    generated: EvidenceFacet,
    execution: ProducerExecutionEvidence,
    fault: ProducerFaultEvidence,
}

#[derive(Debug, Serialize)]
struct ProducerFaultEvidence {
    status: EvidenceStatus,
    terminals: Vec<ProducerFaultTerminalEvidence>,
}

impl ProducerFaultEvidence {
    fn new(terminals: Vec<ProducerFaultTerminalEvidence>) -> Result<Self> {
        ensure!(
            !terminals.is_empty(),
            "producer fault evidence must have at least one terminal"
        );
        ensure!(
            terminals
                .windows(2)
                .all(|pair| pair[0].fact_id < pair[1].fact_id),
            "producer fault terminals must be sorted and unique"
        );
        Ok(Self {
            status: EvidenceStatus::Complete,
            terminals,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProducerFaultTerminalEvidence {
    fact_id: String,
    provider_method: Carrier,
    transaction: Carrier,
    rollback: Carrier,
    commit_unknown: Carrier,
    rollback_failed: Carrier,
    no_replay: Carrier,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProducerExecutionEvidence {
    status: EvidenceStatus,
    route: Carrier,
    mounted_handler: Carrier,
    terminals: Vec<ProducerTerminalEvidence>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProducerTerminalEvidence {
    fact_id: String,
    domain_path: Vec<Carrier>,
    port_method: Carrier,
    provider_method: Carrier,
    production_composition: ProductionCompositionEvidence,
    transaction: Carrier,
    capability: Carrier,
    append: Carrier,
    settlement: Carrier,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProductionCompositionEvidence {
    runtime_entry: Carrier,
    runtime_assembly: Carrier,
    runtime_module: Carrier,
    wire: Carrier,
    service_constructor: String,
    provider_factory: String,
}

#[derive(Debug, Serialize)]
struct EvidenceFacet {
    status: EvidenceStatus,
    carriers: Vec<Carrier>,
}

impl EvidenceFacet {
    fn new(mut carriers: Vec<Carrier>) -> Result<Self> {
        ensure!(!carriers.is_empty(), "evidence facet must not be empty");
        carriers.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        for pair in carriers.windows(2) {
            ensure!(
                pair[0] != pair[1],
                "evidence facet contains duplicate carrier"
            );
        }
        Ok(Self {
            status: EvidenceStatus::Complete,
            carriers,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceStatus {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Carrier {
    kind: CarrierKind,
    path: RepoRelativePath,
    symbol: String,
}

impl Carrier {
    fn new(root: &Path, kind: CarrierKind, path: &str, symbol: &str) -> Result<Self> {
        ensure!(!symbol.is_empty(), "carrier symbol is empty");
        ensure!(
            !symbol.chars().any(char::is_control),
            "carrier symbol contains control character"
        );
        let path = RepoRelativePath::new(root, path)?;
        match kind {
            CarrierKind::RustSymbol => validate_rust_symbol(root, &path.0, symbol)?,
            CarrierKind::RustType => validate_rust_type(root, &path.0, symbol)?,
            CarrierKind::Manifest | CarrierKind::FaultFixture => {}
        }
        Ok(Self {
            kind,
            path,
            symbol: symbol.to_string(),
        })
    }

    fn sort_key(&self) -> (&str, &str, CarrierKind) {
        (&self.path.0, &self.symbol, self.kind)
    }
}

fn validate_rust_type(root: &Path, repo_path: &str, symbol: &str) -> Result<()> {
    ensure!(
        !repo_path.starts_with("generated/src/"),
        "generated carriers must use fully-qualified Rust symbols rather than source-local types"
    );
    let ty = syn::parse_str::<syn::Type>(symbol)
        .with_context(|| format!("Rust type carrier `{symbol}` is malformed"))?;
    let names = rust_type_item_names(&ty)?;
    ensure!(
        !names.is_empty(),
        "Rust type carrier `{symbol}` names no source item"
    );
    let source_path = root.join(repo_path);
    let source = generated_file::read_stable_utf8_file(
        &source_path,
        MAX_RUST_CARRIER_BYTES,
        "Rust type carrier",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("cannot parse Rust type carrier {}", source_path.display()))?;
    for name in names {
        validate_non_generated_rust_symbol(&syntax.items, &[name.as_str()]).with_context(|| {
            format!(
                "Rust type carrier `{symbol}` component `{name}` does not name one exact production item in {repo_path}"
            )
        })?;
    }
    Ok(())
}

fn rust_type_item_names(ty: &syn::Type) -> Result<BTreeSet<String>> {
    fn collect(ty: &syn::Type, names: &mut BTreeSet<String>) -> Result<()> {
        let syn::Type::Path(path) = ty else {
            bail!("Rust type carrier permits only named path types")
        };
        ensure!(
            path.qself.is_none(),
            "Rust type carrier cannot use qualified self"
        );
        let segment = path
            .path
            .segments
            .last()
            .context("Rust type carrier path is empty")?;
        names.insert(segment.ident.to_string());
        match &segment.arguments {
            syn::PathArguments::None => {}
            syn::PathArguments::AngleBracketed(arguments) => {
                for argument in &arguments.args {
                    match argument {
                        syn::GenericArgument::Lifetime(_) => {}
                        syn::GenericArgument::Type(ty) => collect(ty, names)?,
                        _ => bail!(
                            "Rust type carrier generic arguments may contain only lifetimes and named types"
                        ),
                    }
                }
            }
            syn::PathArguments::Parenthesized(_) => {
                bail!("Rust type carrier cannot use function-trait syntax")
            }
        }
        Ok(())
    }

    let mut names = BTreeSet::new();
    collect(ty, &mut names)?;
    Ok(names)
}

fn validate_rust_symbol(root: &Path, repo_path: &str, symbol: &str) -> Result<()> {
    let local_segments = rust_symbol_local_segments(repo_path, symbol)?;
    let source_path = root.join(repo_path);
    let source = generated_file::read_stable_utf8_file(
        &source_path,
        MAX_RUST_CARRIER_BYTES,
        "Rust carrier",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("cannot parse Rust carrier {}", source_path.display()))?;
    if repo_path.starts_with("generated/src/") {
        let item = find_rust_item(&syntax.items, &local_segments).with_context(|| {
            format!("Rust carrier symbol `{symbol}` does not name a real item in {repo_path}")
        })?;
        ensure!(
            !item_is_conditionally_compiled(item),
            "Rust carrier symbol `{symbol}` is conditionally compiled"
        );
    } else {
        validate_non_generated_rust_symbol(&syntax.items, &local_segments).with_context(|| {
            format!("Rust carrier symbol `{symbol}` does not name one exact production item or method in {repo_path}")
        })?;
    }
    Ok(())
}

fn rust_symbol_local_segments<'a>(repo_path: &str, symbol: &'a str) -> Result<Vec<&'a str>> {
    let path = Path::new(repo_path);
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.len() == 4
        && components[0] == "generated"
        && components[1] == "src"
        && components[3].ends_with(".rs")
    {
        let module = components[3]
            .strip_suffix(".rs")
            .context("generated Rust carrier lacks .rs suffix")?;
        let prefix = format!("generated::{}::{module}::", components[2]);
        let local = symbol.strip_prefix(&prefix).with_context(|| {
            format!("generated Rust carrier FQN `{symbol}` does not match `{repo_path}`")
        })?;
        let segments = local.split("::").collect::<Vec<_>>();
        ensure!(
            !segments.is_empty() && segments.iter().all(|segment| !segment.is_empty()),
            "Rust carrier FQN is empty or malformed"
        );
        return Ok(segments);
    }
    let segments = symbol.split("::").collect::<Vec<_>>();
    ensure!(
        matches!(segments.len(), 1 | 2)
            && segments
                .iter()
                .all(|segment| syn::parse_str::<syn::Ident>(segment).is_ok()),
        "non-generated Rust carrier must use `Item` or exact `Type::method` / `Trait::method` syntax"
    );
    Ok(segments)
}

fn validate_non_generated_rust_symbol(items: &[syn::Item], segments: &[&str]) -> Option<()> {
    match segments {
        [item_name] => {
            let item = items
                .iter()
                .find(|item| rust_item_ident(item).is_some_and(|ident| ident == *item_name))?;
            (!item_is_conditionally_compiled(item)).then_some(())
        }
        [owner, method] => {
            let mut matches = 0usize;
            for item in items {
                match item {
                    syn::Item::Trait(item)
                        if item.ident == *owner
                            && !attrs_are_conditional(&item.attrs)
                            && item.items.iter().any(|trait_item| {
                                matches!(
                                    trait_item,
                                    syn::TraitItem::Fn(function)
                                        if function.sig.ident == *method
                                            && !attrs_are_conditional(&function.attrs)
                                )
                            }) =>
                    {
                        matches += 1;
                    }
                    syn::Item::Impl(item)
                        if !attrs_are_conditional(&item.attrs)
                            && type_last_ident(&item.self_ty).as_deref() == Some(*owner)
                            && item.items.iter().any(|impl_item| {
                                matches!(
                                    impl_item,
                                    syn::ImplItem::Fn(function)
                                        if function.sig.ident == *method
                                            && !attrs_are_conditional(&function.attrs)
                                )
                            }) =>
                    {
                        matches += 1;
                    }
                    _ => {}
                }
            }
            (matches == 1).then_some(())
        }
        _ => None,
    }
}

fn type_last_ident(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn attrs_are_conditional(attrs: &[syn::Attribute]) -> bool {
    use quote::ToTokens as _;

    attrs.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || attribute.path().is_ident("cfg_attr")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .meta
                    .to_token_stream()
                    .to_string()
                    .split(|character: char| !character.is_alphanumeric() && character != '_')
                    .any(|token| token == "test"))
    })
}

fn find_rust_item<'a>(items: &'a [syn::Item], segments: &[&str]) -> Option<&'a syn::Item> {
    let (head, tail) = segments.split_first()?;
    let item = items
        .iter()
        .find(|item| rust_item_ident(item).is_some_and(|ident| ident == *head))?;
    if tail.is_empty() {
        return Some(item);
    }
    if item_is_conditionally_compiled(item) {
        return None;
    }
    let syn::Item::Mod(module) = item else {
        return None;
    };
    let (_, nested) = module.content.as_ref()?;
    find_rust_item(nested, tail)
}

fn rust_item_ident(item: &syn::Item) -> Option<&syn::Ident> {
    match item {
        syn::Item::Const(item) => Some(&item.ident),
        syn::Item::Enum(item) => Some(&item.ident),
        syn::Item::Fn(item) => Some(&item.sig.ident),
        syn::Item::Mod(item) => Some(&item.ident),
        syn::Item::Static(item) => Some(&item.ident),
        syn::Item::Struct(item) => Some(&item.ident),
        syn::Item::Trait(item) => Some(&item.ident),
        syn::Item::TraitAlias(item) => Some(&item.ident),
        syn::Item::Type(item) => Some(&item.ident),
        syn::Item::Union(item) => Some(&item.ident),
        _ => None,
    }
}

fn item_is_conditionally_compiled(item: &syn::Item) -> bool {
    let attrs = match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        _ => return true,
    };
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CarrierKind {
    Manifest,
    RustSymbol,
    RustType,
    FaultFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct RepoRelativePath(String);

impl RepoRelativePath {
    fn new(root: &Path, value: &str) -> Result<Self> {
        validate_repo_relative_path(root, value)?;
        Ok(Self(value.to_string()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn policy_carrier_accepts_exact_assembly_private_trait_impl() -> anyhow::Result<()> {
        let syntax = syn::parse_file(
            r#"
            struct PgAuditConsumerTx;
            impl ConsumerTxHandler<policy::TransactionalOnly> for PgAuditConsumerTx {
                type CommitProof = PgConsumerTxCommitProof;
                fn handle(&self) {}
            }
            "#,
        )?;
        verify_policy_symbol_in_syntax(
            &syntax,
            "handler",
            PolicySymbolSpec {
                repo_path: "synthetic.rs",
                symbol: "PgAuditConsumerTx::handle",
                required_trait: Some("ConsumerTxHandler<policy::TransactionalOnly>"),
                required_call: None,
            },
        )?;
        Ok(())
    }

    #[test]
    fn policy_chain_rejects_unknown_subscription_identity() -> anyhow::Result<()> {
        let subscription = SubscriptionIdentity {
            consumer: "audit".to_string(),
            group: "audit.dead-helper".to_string(),
            external_effect_policy: AssuranceExternalEffectPolicy::TransactionalOnly,
        };
        let Err(error) = subscription_policy_chain(&subscription) else {
            bail!("unknown group inherited a known consumer policy chain");
        };
        assert!(
            error.to_string().contains(
                "active subscription audit/audit.dead-helper with policy TransactionalOnly has no closed production policy chain"
            ),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn policy_carrier_rejects_dead_helper_bait() -> anyhow::Result<()> {
        let syntax = syn::parse_file(
            r#"
            fn register_audit_subscriber() {
                reg.subscriber();
            }

            fn dead_helper() {
                let _ = SubscriberCapability::AdapterNativeTransactional;
            }
            "#,
        )?;
        let Err(error) = verify_policy_symbol_in_syntax(
            &syntax,
            "registration",
            PolicySymbolSpec {
                repo_path: "synthetic.rs",
                symbol: "register_audit_subscriber",
                required_trait: None,
                required_call: Some(PolicyCallRequirement::exact(
                    "reg.subscriber",
                    ["SubscriberCapability::AdapterNativeTransactional", ""],
                )),
            },
        ) else {
            bail!("unreachable helper masqueraded as policy evidence");
        };
        assert!(
            error
                .to_string()
                .contains("register_audit_subscriber is outside the closed execution chain"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn policy_carrier_rejects_nested_dead_helper_bait() -> anyhow::Result<()> {
        let syntax = syn::parse_file(
            r#"
            fn register_audit_subscriber() {
                fn dead_helper() {
                    reg.subscriber(SubscriberCapability::AdapterNativeTransactional);
                }
                live_registration();
            }
            "#,
        )?;
        let Err(error) = verify_policy_symbol_in_syntax(
            &syntax,
            "registration",
            PolicySymbolSpec {
                repo_path: "synthetic.rs",
                symbol: "register_audit_subscriber",
                required_trait: None,
                required_call: Some(PolicyCallRequirement::exact(
                    "reg.subscriber",
                    ["SubscriberCapability::AdapterNativeTransactional", ""],
                )),
            },
        ) else {
            bail!("nested unreachable helper masqueraded as policy evidence");
        };
        assert!(
            error
                .to_string()
                .contains("register_audit_subscriber is outside the closed execution chain"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn policy_carrier_rejects_if_false_bait() -> anyhow::Result<()> {
        let syntax = syn::parse_file(
            r#"
            fn register_audit_subscriber() {
                if false {
                    reg.subscriber(SubscriberCapability::AdapterNativeTransactional);
                }
                live_registration();
            }
            "#,
        )?;
        let Err(error) = verify_policy_symbol_in_syntax(
            &syntax,
            "registration",
            PolicySymbolSpec {
                repo_path: "synthetic.rs",
                symbol: "register_audit_subscriber",
                required_trait: None,
                required_call: Some(PolicyCallRequirement::exact(
                    "reg.subscriber",
                    ["SubscriberCapability::AdapterNativeTransactional", ""],
                )),
            },
        ) else {
            bail!("statically unreachable branch masqueraded as policy evidence");
        };
        assert!(
            error
                .to_string()
                .contains("register_audit_subscriber is outside the closed execution chain"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn policy_executor_rejects_symbol_without_worker_edge() -> anyhow::Result<()> {
        let syntax = syn::parse_file(
            r#"
            fn consumer_tx_worker_spec() {
                build_worker();
            }

            fn spawn_consumer_ackable_tx_subscriber() {}
            "#,
        )?;
        let Err(error) = verify_policy_call_edge_in_syntax(
            &syntax,
            "policy executor",
            "synthetic.rs",
            "consumer_tx_worker_spec",
            PolicyCallRequirement::exact("spawn_consumer_ackable_tx_subscriber", ["", ""]),
        ) else {
            bail!("executor symbol existence masqueraded as a worker call edge");
        };
        assert!(
            error
                .to_string()
                .contains("missing reachable call `spawn_consumer_ackable_tx_subscriber`"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: red fixture must fail verify_policy_call_edge_in_syntax.
    fn policy_executor_only_accepts_worker_edge_in_deferred_funnel() -> anyhow::Result<()> {
        let green = syn::parse_file(
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::consumer_deferred(identity, &admission, move |token, consumer_admission| {
                    spawn_consumer_ackable_tx_subscriber(token, consumer_admission)
                })
            }
            "#,
        )?;
        verify_policy_call_edge_in_syntax(
            &green,
            "policy executor",
            "synthetic.rs",
            "worker_spec",
            PolicyCallRequirement::exact("spawn_consumer_ackable_tx_subscriber", ["", ""]),
        )?;

        for red in [
            r#"
            fn worker_spec() -> WorkerSpec {
                let _bait = spawn_consumer_ackable_tx_subscriber(fake_token, fake_admission);
                WorkerSpec::observational_deferred(move |token| harmless_worker(token))
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::deferred(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::observational_deferred(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::relay_deferred(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::writes_deferred(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::observational_phase_one(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::consumer_phase_one(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::relay_phase_one(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() -> WorkerSpec {
                WorkerSpec::writes_phase_one(move |token| {
                    spawn_consumer_ackable_tx_subscriber(token)
                })
            }
            "#,
            r#"
            fn worker_spec() {
                let hidden = move |token| spawn_consumer_ackable_tx_subscriber(token);
                build_worker(hidden)
            }
            "#,
        ] {
            let syntax = syn::parse_file(red)?;
            let error = verify_policy_call_edge_in_syntax(
                &syntax,
                "policy executor",
                "synthetic.rs",
                "worker_spec",
                PolicyCallRequirement::exact("spawn_consumer_ackable_tx_subscriber", ["", ""]),
            )
            .expect_err("non-deferred closure must not masquerade as the ConsumerTx sink");
            assert!(
                error
                    .to_string()
                    .contains("missing reachable call `spawn_consumer_ackable_tx_subscriber`"),
                "unexpected error: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn carrier_paths_reject_escapes_backslashes_and_symlinks() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("l2-assurance-path");
        fs::create_dir_all(root.join("contracts"))?;
        fs::write(root.join("contracts/event.toml"), "event")?;
        for invalid in [
            root.join("contracts/event.toml")
                .to_string_lossy()
                .to_string(),
            "../contracts/event.toml".to_string(),
            "contracts/../event.toml".to_string(),
            "contracts\\event.toml".to_string(),
            "contracts/event\n.toml".to_string(),
        ] {
            assert!(
                validate_repo_relative_path(&root, &invalid).is_err(),
                "unsafe carrier accepted: {invalid:?}"
            );
        }
        validate_repo_relative_path(&root, "contracts/event.toml")?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("event.toml", root.join("contracts/linked.toml"))?;
            assert!(validate_repo_relative_path(&root, "contracts/linked.toml").is_err());
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn complete_evidence_rejects_empty_facets() {
        assert!(EvidenceFacet::new(Vec::new()).is_err());
    }

    #[test]
    fn rust_symbol_carrier_rejects_missing_and_test_only_items() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("l2-assurance-rust-symbol");
        fs::create_dir_all(root.join("generated/src/event"))?;
        fs::create_dir_all(root.join("crates/demo/src"))?;
        fs::write(
            root.join("generated/src/event/identity_v1.rs"),
            r#"
pub mod session_created {
    pub const SPEC: () = ();
    #[cfg(test)]
    pub const TEST_ONLY: () = ();
}
#[cfg(test)]
pub mod test_parent {
    pub const SPEC: () = ();
}
#[cfg_attr(feature = "synthetic", allow(dead_code))]
pub mod cfg_attr_parent {
    pub const SPEC: () = ();
}
"#,
        )?;

        Carrier::new(
            &root,
            CarrierKind::RustSymbol,
            "generated/src/event/identity_v1.rs",
            "generated::event::identity_v1::session_created::SPEC",
        )?;
        assert!(
            Carrier::new(
                &root,
                CarrierKind::RustSymbol,
                "generated/src/event/identity_v1.rs",
                "generated::event::identity_v1::session_created::MISSING",
            )
            .is_err()
        );
        for parent in ["test_parent", "cfg_attr_parent"] {
            assert!(
                Carrier::new(
                    &root,
                    CarrierKind::RustSymbol,
                    "generated/src/event/identity_v1.rs",
                    &format!("generated::event::identity_v1::{parent}::SPEC"),
                )
                .is_err(),
                "conditionally compiled parent module was accepted: {parent}"
            );
        }
        assert!(
            Carrier::new(
                &root,
                CarrierKind::RustSymbol,
                "generated/src/event/identity_v1.rs",
                "generated::event::identity_v1::session_created::TEST_ONLY",
            )
            .is_err()
        );
        fs::write(
            root.join("crates/demo/src/lib.rs"),
            r#"
pub trait DemoPort {
    fn commit(&self);
}
pub struct DemoProvider;
impl DemoPort for DemoProvider {
    fn commit(&self) {}
}
#[cfg(test)]
impl DemoProvider {
    fn decoy(&self) {}
}
"#,
        )?;
        Carrier::new(
            &root,
            CarrierKind::RustSymbol,
            "crates/demo/src/lib.rs",
            "DemoPort::commit",
        )?;
        Carrier::new(
            &root,
            CarrierKind::RustSymbol,
            "crates/demo/src/lib.rs",
            "DemoProvider::commit",
        )?;
        assert!(
            Carrier::new(
                &root,
                CarrierKind::RustSymbol,
                "crates/demo/src/lib.rs",
                "DemoProvider::decoy",
            )
            .is_err()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn output_publish_rejects_parent_replaced_by_symlink_after_precheck() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("l2-assurance-parent-swap");
        let outside = crate::testutil::unique_tmp("l2-assurance-parent-outside");
        fs::create_dir_all(root.join("generated"))?;
        fs::create_dir_all(&outside)?;
        let output = root.join(OUTPUT);
        fs::write(&output, b"old\n")?;
        validate_output_path(&root, &output)?;

        fs::rename(root.join("generated"), root.join("generated-real"))?;
        symlink(&outside, root.join("generated"))?;
        assert!(generated_file::atomic_replace(&output, b"new\n").is_err());
        assert!(!outside.join("l2-assurance.json").exists());

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn generation_accepts_missing_canonical_parent_for_safe_atomic_creation() -> anyhow::Result<()>
    {
        let root = crate::testutil::unique_tmp("l2-assurance-missing-parent");
        fs::create_dir_all(&root)?;
        let output = root.join(OUTPUT);

        validate_output_path(&root, &output)?;
        generated_file::atomic_replace(&output, b"generated\n")?;
        assert_eq!(fs::read(&output)?, b"generated\n");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn output_publish_rejects_ancestor_replaced_by_symlink_after_precheck() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("l2-assurance-ancestor-swap");
        let outside = crate::testutil::unique_tmp("l2-assurance-ancestor-outside");
        let moved = root.with_file_name(format!(
            "{}-real",
            root.file_name()
                .and_then(|name| name.to_str())
                .context("temporary root is not UTF-8")?
        ));
        fs::create_dir_all(root.join("generated"))?;
        fs::create_dir_all(outside.join("generated"))?;
        let output = root.join(OUTPUT);
        fs::write(&output, b"old\n")?;
        validate_output_path(&root, &output)?;

        fs::rename(&root, &moved)?;
        symlink(&outside, &root)?;
        assert!(generated_file::atomic_replace(&output, b"new\n").is_err());
        assert!(!outside.join(OUTPUT).exists());

        fs::remove_file(&root)?;
        fs::remove_dir_all(moved)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[test]
    fn exact_set_rejects_equal_size_wrong_identity() {
        let expected = ["identity.one".to_string(), "identity.two".to_string()];
        let actual = ["identity.one".to_string(), "identity.wrong".to_string()];
        assert!(ensure_exact_ids("synthetic", expected.iter(), actual.iter()).is_err());
    }

    #[test]
    fn exact_set_rejects_duplicate_missing_and_extra_identities() {
        let expected = ["identity.one".to_string(), "identity.two".to_string()];
        let duplicate = [
            "identity.one".to_string(),
            "identity.two".to_string(),
            "identity.two".to_string(),
        ];
        let missing = ["identity.one".to_string()];
        let extra = [
            "identity.one".to_string(),
            "identity.two".to_string(),
            "identity.extra".to_string(),
        ];

        assert!(ensure_exact_ids("duplicate", expected.iter(), duplicate.iter()).is_err());
        assert!(ensure_exact_ids("missing", expected.iter(), missing.iter()).is_err());
        assert!(ensure_exact_ids("extra", expected.iter(), extra.iter()).is_err());
    }

    #[test]
    fn check_rejects_missing_tampered_and_crlf_without_writing() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("l2-assurance-check");
        fs::create_dir_all(&root)?;
        let output = root.join("inventory.json");
        let expected = b"{\n  \"schemaVersion\": 1\n}\n";
        assert!(check_rendered_file(&output, expected).is_err());
        fs::write(&output, b"tampered\n")?;
        assert!(check_rendered_file(&output, expected).is_err());
        assert_eq!(fs::read(&output)?, b"tampered\n");
        fs::write(&output, b"{\r\n  \"schemaVersion\": 1\r\n}\r\n")?;
        assert!(check_rendered_file(&output, expected).is_err());
        assert_eq!(fs::read(&output)?, b"{\r\n  \"schemaVersion\": 1\r\n}\r\n");
        fs::write(&output, expected)?;
        check_rendered_file(&output, expected)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn check_rejects_artifact_replaced_after_open() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("l2-assurance-check-replacement");
        fs::create_dir_all(&root)?;
        let output = root.join("inventory.json");
        let replacement = root.join("replacement.json");
        let expected = b"{\n  \"schemaVersion\": 1\n}\n";
        fs::write(&output, expected)?;
        fs::write(&replacement, expected)?;

        let result = check_rendered_file_with_hook(&output, expected, || {
            let opened = root.join("opened.json");
            assert!(fs::rename(&output, opened).is_ok());
            assert!(fs::rename(&replacement, &output).is_ok());
        });
        assert!(result.is_err(), "pathname replacement must fail closed");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn governance_failure_reports_every_finding() {
        #[derive(Debug, Clone, Copy)]
        enum SyntheticRule {
            First,
            Second,
        }
        let findings = vec![
            crate::diagnostic::finding(SyntheticRule::First, "one", "first detail"),
            crate::diagnostic::finding(SyntheticRule::Second, "two", "second detail"),
        ];
        let error = ensure_findings_empty("synthetic", &findings)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("[First] one: first detail"), "{error}");
        assert!(error.contains("[Second] two: second detail"), "{error}");
    }

    fn assert_inventory_identity_projection(inventory: &Inventory) {
        let producer_ids = inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Producer(record) => Some(record.contract_id.as_str()),
                AssuranceRecord::Fact(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let fact_ids = inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Fact(record) => Some(record.contract_id.as_str()),
                AssuranceRecord::Producer(_) => None,
            })
            .collect::<BTreeSet<_>>();
        assert!(!producer_ids.is_empty(), "producer projection is empty");
        assert!(!fact_ids.is_empty(), "fact projection is empty");
        assert_eq!(inventory.producer_count, producer_ids.len());
        assert_eq!(inventory.fact_count, fact_ids.len());
        assert!(producer_ids.is_disjoint(&fact_ids));
        assert_eq!(
            producer_ids.union(&fact_ids).count(),
            inventory.contracts.len(),
            "record identities must be unique across roles"
        );
    }

    #[test]
    fn workspace_inventory_is_exact_and_deterministic() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let workspace_facts = command_facts.get()?;
        let first = build_inventory(&root, workspace_facts)?;
        let first_bytes = render(&first)?;
        let second_bytes = render(&build_inventory(&root, workspace_facts)?)?;
        assert_inventory_identity_projection(&first);
        let login = first
            .contracts
            .iter()
            .find_map(|record| match record {
                AssuranceRecord::Producer(record) if record.contract_id == "identity.login" => {
                    Some(record)
                }
                _ => None,
            })
            .context("identity.login producer disappeared")?;
        assert_eq!(
            login.evidence.execution.mounted_handler.symbol,
            "login_handler"
        );
        assert!(
            login
                .evidence
                .fault
                .terminals
                .iter()
                .all(|terminal| terminal.no_replay.symbol == "ProducerTxAttempt::into_result"),
            "plain producer terminals must record their actual non-retry settlement consumer"
        );
        let config_publish = first
            .contracts
            .iter()
            .find_map(|record| match record {
                AssuranceRecord::Producer(record)
                    if record.contract_id == "settings.config-publish" =>
                {
                    Some(record)
                }
                _ => None,
            })
            .context("settings.config-publish producer disappeared")?;
        assert!(
            config_publish
                .evidence
                .fault
                .terminals
                .iter()
                .all(|terminal| {
                    terminal.no_replay.symbol == "LocalTxAttempt::into_retry_result"
                }),
            "retry producer terminals must record the retry runner's actual settlement consumer"
        );
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_bytes.last(), Some(&b'\n'));
        assert!(!first_bytes.contains(&b'\r'));
        let text = String::from_utf8(first_bytes)?;
        assert!(!text.contains("_seed"));
        assert!(!text.contains("/Users/"));
        assert!(!text.contains("schemaHash\": \"HEAD"));
        Ok(())
    }

    #[test]
    fn workspace_refresh_rejects_localtx_and_joins_security_event_producers() -> anyhow::Result<()>
    {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let inventory = build_inventory(&root, command_facts.get()?)?;
        let security_event_producers = inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Producer(record)
                    if record
                        .emitted_facts
                        .iter()
                        .any(|fact| fact == "identity.security-event") =>
                {
                    Some(record.contract_id.as_str())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();

        let refresh = inventory
            .contracts
            .iter()
            .find_map(|record| match record {
                AssuranceRecord::Producer(record) if record.contract_id == "identity.refresh" => {
                    Some(record)
                }
                _ => None,
            })
            .context(
                "identity.refresh must reject LocalTx and enter the closed OutboxFact producer inventory",
            )?;
        assert_eq!(
            refresh.emitted_facts,
            ["identity.security-event"],
            "refresh reuse containment must emit only the canonical security fact"
        );
        assert_eq!(
            security_event_producers,
            BTreeSet::from([
                "identity.account-status-set",
                "identity.logout",
                "identity.logout-all",
                "identity.password-change",
                "identity.refresh",
            ]),
            "security-event producer identity set drift"
        );
        Ok(())
    }

    #[test]
    fn workspace_fault_evidence_uses_exact_runner_symbols() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let inventory = build_inventory(&root, command_facts.get()?)?;
        let session_created = inventory
            .contracts
            .iter()
            .find_map(|record| match record {
                AssuranceRecord::Fact(record)
                    if record.contract_id == "identity.session-created" =>
                {
                    Some(record)
                }
                _ => None,
            })
            .context("identity.session-created fact disappeared")?;
        let runner_symbols = session_created
            .evidence
            .fault
            .carriers
            .iter()
            .filter(|carrier| carrier.kind == CarrierKind::RustSymbol)
            .map(|carrier| carrier.symbol.as_str())
            .collect::<BTreeSet<_>>();

        assert!(
            !runner_symbols.contains("READY_CASE_RUNNERS"),
            "the runner table must not masquerade as case execution evidence"
        );
        for expected in [
            "run_outbox_confirm_lost_channel_close",
            "run_outbox_stale_contender_settle",
            "run_outbox_deadline_expired_settle",
        ] {
            assert!(
                runner_symbols.contains(expected),
                "missing exact runner carrier `{expected}`: {runner_symbols:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn workspace_fact_effect_evidence_closes_all_policy_stages() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let inventory = build_inventory(&root, command_facts.get()?)?;
        let facts = inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Fact(record) => Some(record),
                AssuranceRecord::Producer(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(!facts.is_empty(), "active fact projection is empty");
        let mut subscription_ids = BTreeSet::new();
        for fact in facts {
            let carriers = fact
                .evidence
                .effect
                .carriers
                .iter()
                .map(|carrier| (carrier.path.0.as_str(), carrier.symbol.as_str()))
                .collect::<BTreeSet<_>>();
            for subscription in &fact.subscriptions {
                assert!(
                    subscription_ids.insert((
                        fact.contract_id.as_str(),
                        subscription.consumer.as_str(),
                        subscription.group.as_str(),
                    )),
                    "duplicate active subscription identity: {}/{}/{}",
                    fact.contract_id,
                    subscription.consumer,
                    subscription.group
                );
                let registration_path =
                    format!("crates/{}/src/application.rs", subscription.consumer);
                assert_eq!(
                    carriers
                        .iter()
                        .filter(|(path, _)| *path == registration_path)
                        .count(),
                    1,
                    "{} effect evidence must have one exact registration capability for {}: {carriers:?}",
                    fact.contract_id,
                    subscription.consumer
                );
                let handler = match subscription.external_effect_policy {
                    AssuranceExternalEffectPolicy::TransactionalOnly => "PgAuditConsumerTx::handle",
                    AssuranceExternalEffectPolicy::Reconcile => "PgSettingsConsumerTx::handle",
                    AssuranceExternalEffectPolicy::IdempotencyKey
                    | AssuranceExternalEffectPolicy::Compensated => {
                        bail!(
                            "active subscription {}/{} has unsupported policy {:?}",
                            subscription.consumer,
                            subscription.group,
                            subscription.external_effect_policy
                        )
                    }
                };
                for expected in [
                    ("composition/eventing/src/lib.rs", "resolve_parts"),
                    ("composition/eventing/src/consumer_tx.rs", handler),
                    (
                        "composition/eventing/src/consumer_tx.rs",
                        "spawn_consumer_ackable_tx_subscriber",
                    ),
                ] {
                    assert!(
                        carriers.contains(&expected),
                        "{} effect evidence lacks exact policy carrier {expected:?}: {carriers:?}",
                        fact.contract_id
                    );
                }
            }
            assert!(
                carriers
                    .iter()
                    .all(|(path, _)| !path.starts_with("generated/src/event/")),
                "{} generated SPEC must not masquerade as effect execution evidence",
                fact.contract_id
            );
        }
        assert!(
            !subscription_ids.is_empty(),
            "active subscription projection is empty"
        );
        Ok(())
    }
}
