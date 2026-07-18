use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use generated::{event, http};
use serde::Deserialize;
use vocab::HttpConsistencyLevel;

const ASSURANCE_JSON: &str = include_str!("../l2-assurance.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssuranceInventory {
    schema_version: u32,
    producer_count: usize,
    fact_count: usize,
    contracts: Vec<AssuranceRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "camelCase", deny_unknown_fields)]
enum AssuranceRecord {
    #[serde(rename_all = "camelCase")]
    Producer {
        contract_id: String,
        domain: String,
        version: String,
        status: RecordStatus,
        emitted_facts: Vec<String>,
        evidence: CompleteEvidence,
    },
    #[serde(rename_all = "camelCase")]
    Fact {
        contract_id: String,
        domain: String,
        version: String,
        status: RecordStatus,
        topic: String,
        subscriptions: Vec<SubscriptionIdentity>,
        evidence: CompleteEvidence,
    },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum RecordStatus {
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscriptionIdentity {
    consumer: String,
    group: String,
    external_effect_policy: AssuranceExternalEffectPolicy,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AssuranceExternalEffectPolicy {
    TransactionalOnly,
    IdempotencyKey,
    Reconcile,
    Compensated,
}

impl AssuranceExternalEffectPolicy {
    fn as_wire(&self) -> &'static str {
        match self {
            Self::TransactionalOnly => "transactional-only",
            Self::IdempotencyKey => "idempotency-key",
            Self::Reconcile => "reconcile",
            Self::Compensated => "compensated",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteEvidence {
    contract: EvidenceFacet,
    generated: EvidenceFacet,
    runtime: EvidenceFacet,
    effect: EvidenceFacet,
    fault: EvidenceFacet,
}

impl CompleteEvidence {
    fn facets(&self) -> [&EvidenceFacet; 5] {
        [
            &self.contract,
            &self.generated,
            &self.runtime,
            &self.effect,
            &self.fault,
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceFacet {
    status: FacetStatus,
    carriers: Vec<EvidenceCarrier>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum FacetStatus {
    Complete,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceCarrier {
    kind: CarrierKind,
    path: String,
    symbol: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum CarrierKind {
    Manifest,
    RustSymbol,
    FaultFixture,
}

#[test]
fn committed_l2_assurance_is_closed_and_matches_compiled_registries()
-> Result<(), serde_json::Error> {
    let inventory: AssuranceInventory = serde_json::from_str(ASSURANCE_JSON)?;

    assert_eq!(inventory.schema_version, 2);
    assert_eq!(inventory.producer_count, 9);
    assert_eq!(inventory.fact_count, 5);
    assert_eq!(inventory.contracts.len(), 14);

    let compiled_producers: BTreeMap<_, _> = http::SPECS
        .iter()
        .filter(|spec| spec.route.consistency_level() == HttpConsistencyLevel::OutboxFact)
        .map(|spec| (spec.route.contract_id(), spec))
        .collect();
    let compiled_producer_bindings: BTreeMap<_, _> = http::OUTBOX_PRODUCERS
        .iter()
        .map(|producer| (producer.route().contract().contract_id(), producer))
        .collect();
    let compiled_facts: BTreeMap<_, _> = event::EVENTS
        .iter()
        .map(|spec| (spec.contract_id(), spec))
        .collect();
    let producer_ids: BTreeSet<_> = inventory
        .contracts
        .iter()
        .filter_map(|record| match record {
            AssuranceRecord::Producer { contract_id, .. } => Some(contract_id.as_str()),
            AssuranceRecord::Fact { .. } => None,
        })
        .collect();
    let compiled_producer_ids: BTreeSet<_> = compiled_producers.keys().copied().collect();
    assert_eq!(producer_ids, compiled_producer_ids);
    assert_eq!(producer_ids.len(), compiled_producer_bindings.len());

    let fact_ids: BTreeSet<_> = inventory
        .contracts
        .iter()
        .filter_map(|record| match record {
            AssuranceRecord::Fact { contract_id, .. } => Some(contract_id.as_str()),
            AssuranceRecord::Producer { .. } => None,
        })
        .collect();
    let compiled_fact_ids: BTreeSet<_> = compiled_facts.keys().copied().collect();
    assert_eq!(fact_ids, compiled_fact_ids);

    assert_eq!(producer_ids.len(), inventory.producer_count);
    assert_eq!(fact_ids.len(), inventory.fact_count);

    let identities: BTreeSet<_> = inventory
        .contracts
        .iter()
        .map(|record| match record {
            AssuranceRecord::Producer { contract_id, .. }
            | AssuranceRecord::Fact { contract_id, .. } => contract_id.as_str(),
        })
        .collect();
    assert_eq!(identities.len(), inventory.contracts.len());

    for record in &inventory.contracts {
        let (contract_id, domain) = record_identity(record);
        assert_ne!(
            domain, "_seed",
            "draft seed entered the assurance inventory"
        );
        assert!(
            !contract_id.starts_with("seed."),
            "draft seed entered the assurance inventory"
        );
        match record {
            AssuranceRecord::Producer { evidence, .. } => {
                assert_producer_runtime(evidence, contract_id, domain);
                assert_producer(
                    record,
                    &fact_ids,
                    &compiled_producers,
                    &compiled_producer_bindings,
                );
            }
            AssuranceRecord::Fact { evidence, .. } => {
                assert_fact_runtime_symbols(
                    evidence,
                    &["bridge_generated_subscriptions", "resolve_consumer_tx_plan"],
                    contract_id,
                );
                assert_fact(record, &compiled_facts);
            }
        }
    }

    Ok(())
}

fn assert_fact_runtime_symbols(evidence: &CompleteEvidence, expected: &[&str], contract_id: &str) {
    let actual = evidence
        .runtime
        .carriers
        .iter()
        .map(|carrier| carrier.symbol.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "{contract_id} runtime carrier drift");
    assert!(
        evidence.runtime.carriers.iter().all(|carrier| {
            carrier.kind == CarrierKind::RustSymbol
                && carrier.path == "assemblies/runtime/src/event_transport.rs"
        }),
        "{contract_id} runtime carriers must be production event-transport symbols"
    );
}

fn assert_producer_runtime(evidence: &CompleteEvidence, contract_id: &str, domain: &str) {
    assert_eq!(
        evidence.runtime.carriers.len(),
        1,
        "{contract_id} must have one canonical producer handler"
    );
    let handler = &evidence.runtime.carriers[0];
    assert_eq!(handler.kind, CarrierKind::RustSymbol, "{contract_id}");
    assert!(
        handler.path.starts_with(&format!("crates/{domain}/src/")) && handler.path.ends_with(".rs"),
        "{contract_id} runtime must be its domain HTTP handler"
    );
    assert!(
        handler.symbol.ends_with("_handler"),
        "{contract_id} runtime must name the route handler"
    );
    assert!(
        evidence.effect.carriers.iter().any(|carrier| {
            carrier.kind == CarrierKind::RustSymbol
                && carrier.path.starts_with(&format!("crates/{domain}/src/"))
        }),
        "{contract_id} lacks domain service/UoW receipt evidence"
    );
    assert!(
        evidence.effect.carriers.iter().any(|carrier| {
            carrier.kind == CarrierKind::RustSymbol
                && carrier.path.starts_with("adapters/postgres/src/")
        }),
        "{contract_id} lacks Postgres receipt authorization evidence"
    );
    assert!(
        evidence.effect.carriers.iter().any(|carrier| {
            carrier.kind == CarrierKind::RustSymbol
                && carrier.path.starts_with("generated/src/http/")
                && carrier.symbol.ends_with("::EFFECT_PROFILE")
        }),
        "{contract_id} lacks generated effect-profile evidence"
    );
}

fn record_identity(record: &AssuranceRecord) -> (&str, &str) {
    match record {
        AssuranceRecord::Producer {
            contract_id,
            domain,
            ..
        }
        | AssuranceRecord::Fact {
            contract_id,
            domain,
            ..
        } => (contract_id, domain),
    }
}

fn assert_producer(
    record: &AssuranceRecord,
    fact_ids: &BTreeSet<&str>,
    compiled: &BTreeMap<&str, &http::HttpSpec>,
    bindings: &BTreeMap<&str, &vocab::http::HttpProducerEvidence>,
) {
    let AssuranceRecord::Producer {
        contract_id,
        domain,
        version,
        status,
        emitted_facts,
        evidence,
    } = record
    else {
        return;
    };
    assert_eq!(status, &RecordStatus::Closed, "{contract_id}");
    assert!(!emitted_facts.is_empty(), "{contract_id}");
    assert_strictly_sorted_and_unique(emitted_facts, contract_id);
    assert!(
        emitted_facts
            .iter()
            .all(|fact| fact_ids.contains(fact.as_str())),
        "{contract_id} emits a fact outside the active compiled fact set"
    );

    let binding = compiled[contract_id.as_str()].route.contract();
    assert_eq!(domain, binding.domain(), "{contract_id}");
    assert_eq!(version, binding.version(), "{contract_id}");
    let compiled_facts = bindings[contract_id.as_str()]
        .emitted_facts()
        .iter()
        .map(|binding| binding.contract_id())
        .collect::<Vec<_>>();
    assert_eq!(emitted_facts, &compiled_facts, "{contract_id}");
    let generated_symbols = evidence
        .generated
        .carriers
        .iter()
        .map(|carrier| carrier.symbol.as_str())
        .collect::<Vec<_>>();
    assert_eq!(generated_symbols.len(), 2, "{contract_id}");
    assert!(
        generated_symbols
            .iter()
            .any(|symbol| symbol.ends_with("::PRODUCER")),
        "{contract_id} lacks generated producer binding"
    );
    assert_complete_evidence(evidence, contract_id);
}

fn assert_fact(record: &AssuranceRecord, compiled: &BTreeMap<&str, &event::EventSpec>) {
    let AssuranceRecord::Fact {
        contract_id,
        domain,
        version,
        status,
        topic,
        subscriptions,
        evidence,
    } = record
    else {
        return;
    };
    assert_eq!(status, &RecordStatus::Closed, "{contract_id}");
    let spec = compiled[contract_id.as_str()];
    assert_eq!(domain, spec.contract().domain(), "{contract_id}");
    assert_eq!(version, spec.schema_version(), "{contract_id}");
    assert_eq!(topic, spec.topic(), "{contract_id}");

    assert!(
        subscriptions.windows(2).all(|pair| {
            (&pair[0].consumer, &pair[0].group) < (&pair[1].consumer, &pair[1].group)
        }),
        "{contract_id} subscriptions must be sorted and unique"
    );
    let actual_subscriptions: Vec<_> = subscriptions
        .iter()
        .map(|subscription| {
            (
                subscription.consumer.as_str(),
                subscription.group.as_str(),
                subscription.external_effect_policy.as_wire(),
            )
        })
        .collect();
    let mut compiled_subscriptions: Vec<_> = spec
        .subscriptions()
        .iter()
        .map(|subscription| {
            (
                subscription.consumer(),
                subscription.group(),
                match subscription.external_effect_policy() {
                    event::ExternalEffectPolicy::TransactionalOnly => "transactional-only",
                    event::ExternalEffectPolicy::IdempotencyKey => "idempotency-key",
                    event::ExternalEffectPolicy::Reconcile => "reconcile",
                    event::ExternalEffectPolicy::Compensated => "compensated",
                },
            )
        })
        .collect();
    compiled_subscriptions.sort_unstable();
    assert_eq!(
        actual_subscriptions, compiled_subscriptions,
        "{contract_id}"
    );
    assert_complete_evidence(evidence, contract_id);
}

fn assert_complete_evidence(evidence: &CompleteEvidence, contract_id: &str) {
    for facet in evidence.facets() {
        assert_eq!(facet.status, FacetStatus::Complete, "{contract_id}");
        assert!(!facet.carriers.is_empty(), "{contract_id}");
        assert!(
            facet.carriers.windows(2).all(|pair| {
                (&pair[0].path, &pair[0].symbol, pair[0].kind)
                    < (&pair[1].path, &pair[1].symbol, pair[1].kind)
            }),
            "{contract_id} carriers must be sorted and unique: {:?}",
            facet.carriers
        );
        for carrier in &facet.carriers {
            assert!(!carrier.symbol.is_empty(), "{contract_id}");
            assert_canonical_repo_relative_path(&carrier.path, contract_id);
        }
    }
    let runner_carriers = evidence
        .fault
        .carriers
        .iter()
        .filter(|carrier| carrier.kind == CarrierKind::RustSymbol)
        .collect::<Vec<_>>();
    assert_eq!(runner_carriers.len(), 1, "{contract_id}");
    assert_eq!(
        (
            runner_carriers[0].path.as_str(),
            runner_carriers[0].symbol.as_str(),
        ),
        (
            "journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs",
            "READY_CASE_RUNNERS",
        ),
        "{contract_id} fault runner carrier drift"
    );
}

fn assert_strictly_sorted_and_unique<T: Ord + std::fmt::Debug>(values: &[T], owner: &str) {
    assert!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "{owner} values must be sorted and unique: {values:?}"
    );
}

fn assert_canonical_repo_relative_path(path: &str, contract_id: &str) {
    assert!(!path.is_empty(), "{contract_id}");
    assert!(!path.contains('\\'), "{contract_id}: {path}");
    assert!(!path.chars().any(char::is_control), "{contract_id}: {path}");
    assert!(Path::new(path).is_relative(), "{contract_id}: {path}");
    assert!(
        path.split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
        "{contract_id}: {path}"
    );
    assert!(
        Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "{contract_id}: {path}"
    );
}
