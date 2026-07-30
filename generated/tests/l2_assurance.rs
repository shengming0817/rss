#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use generated::{event, http};
use vocab::HttpConsistencyLevel;

#[path = "support/l2_assurance.rs"]
mod l2_assurance_support;
use l2_assurance_support::*;

const ASSURANCE_JSON: &str = include_str!("../l2-assurance.json");

const REQUIRED_SESSION_CREATED_INBOX_SCENARIOS: [&str; 3] = [
    "run_inbox_claim_crash_before_commit",
    "run_inbox_commit_before_ack_crash",
    "run_inbox_lease_lost_before_commit",
];

#[test]
fn committed_l2_assurance_is_closed_and_matches_compiled_registries() {
    let inventory = AssuranceInventory::parse_v3(ASSURANCE_JSON).expect("strict v3 inventory");

    assert_eq!(inventory.schema_version, 3);
    assert_exact_ids(
        "producer inventory/generated specs",
        http::SPECS
            .iter()
            .filter(|spec| spec.route.consistency_level() == HttpConsistencyLevel::OutboxFact)
            .map(|spec| spec.route.contract_id().to_owned()),
        inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Producer { contract_id, .. } => Some(contract_id.clone()),
                AssuranceRecord::Fact { .. } => None,
            }),
    )
    .expect("producer inventory must exactly join generated specs");
    assert_exact_ids(
        "producer inventory/generated bindings",
        http::OUTBOX_PRODUCERS
            .iter()
            .map(|producer| producer.route().contract().contract_id().to_owned()),
        inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Producer { contract_id, .. } => Some(contract_id.clone()),
                AssuranceRecord::Fact { .. } => None,
            }),
    )
    .expect("producer inventory must exactly join generated bindings");
    assert_exact_ids(
        "fact inventory/generated events",
        event::EVENTS
            .iter()
            .map(|spec| spec.contract_id().to_owned()),
        inventory
            .contracts
            .iter()
            .filter_map(|record| match record {
                AssuranceRecord::Fact { contract_id, .. } => Some(contract_id.clone()),
                AssuranceRecord::Producer { .. } => None,
            }),
    )
    .expect("fact inventory must exactly join generated events");

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
    assert!(!producer_ids.is_empty(), "producer projection is empty");

    let fact_ids: BTreeSet<_> = inventory
        .contracts
        .iter()
        .filter_map(|record| match record {
            AssuranceRecord::Fact { contract_id, .. } => Some(contract_id.as_str()),
            AssuranceRecord::Producer { .. } => None,
        })
        .collect();
    assert!(!fact_ids.is_empty(), "fact projection is empty");

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
            AssuranceRecord::Producer { .. } => {
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
                    &["bridge_generated_subscriptions", "resolve_parts"],
                    contract_id,
                );
                assert_fact(record, &compiled_facts);
            }
        }
    }
}

#[test]
fn assurance_reader_rejects_v2_and_unknown_fields() {
    let v2 = ASSURANCE_JSON.replacen("\"schemaVersion\": 3", "\"schemaVersion\": 2", 1);
    assert!(AssuranceInventory::parse_v3(&v2).is_err());

    let unknown = ASSURANCE_JSON.replacen(
        "\"producerCount\":",
        "\"legacyProducerEvidence\": true,\n  \"producerCount\":",
        1,
    );
    assert_ne!(unknown, ASSURANCE_JSON);
    assert!(AssuranceInventory::parse_v3(&unknown).is_err());

    let duplicate_schema = ASSURANCE_JSON.replacen(
        "\"schemaVersion\": 3",
        "\"schemaVersion\": 3,\n  \"schemaVersion\": 3",
        1,
    );
    assert!(AssuranceInventory::parse_v3(&duplicate_schema).is_err());
}

#[test]
fn exact_id_join_rejects_wrong_duplicate_missing_and_extra_identities() {
    let expected = ["identity.one", "identity.two"];
    for (label, actual) in [
        ("wrong", vec!["identity.one", "identity.wrong"]),
        (
            "duplicate",
            vec!["identity.one", "identity.two", "identity.two"],
        ),
        ("missing", vec!["identity.one"]),
        (
            "extra",
            vec!["identity.one", "identity.two", "identity.extra"],
        ),
    ] {
        assert!(
            assert_exact_ids(
                label,
                expected.into_iter().map(str::to_owned),
                actual.into_iter().map(str::to_owned),
            )
            .is_err(),
            "{label} identity projection was accepted"
        );
    }
}

#[test]
fn required_session_created_inbox_scenarios_reject_each_missing_runner_or_fixture() {
    let carriers = [
        (CarrierKind::FaultFixture, "inbox-claim-crash-before-commit"),
        (CarrierKind::FaultFixture, "inbox-commit-before-ack-crash"),
        (CarrierKind::FaultFixture, "inbox-lease-lost-before-commit"),
        (
            CarrierKind::RustSymbol,
            "run_inbox_claim_crash_before_commit",
        ),
        (CarrierKind::RustSymbol, "run_inbox_commit_before_ack_crash"),
        (
            CarrierKind::RustSymbol,
            "run_inbox_lease_lost_before_commit",
        ),
    ];
    assert!(
        assert_required_inbox_security_scenarios("identity.session-created", carriers.into_iter(),)
            .is_ok()
    );

    for runner in REQUIRED_SESSION_CREATED_INBOX_SCENARIOS {
        let missing_runner = carriers.into_iter().filter(|(_, symbol)| *symbol != runner);
        let error =
            assert_required_inbox_security_scenarios("identity.session-created", missing_runner)
                .expect_err("missing required inbox runner must be rejected");
        assert!(error.contains(runner), "{error}");

        let fixture = inbox_fixture_id(runner);
        let missing_fixture = carriers
            .into_iter()
            .filter(|(_, symbol)| *symbol != fixture);
        let error =
            assert_required_inbox_security_scenarios("identity.session-created", missing_fixture)
                .expect_err("missing required inbox fixture must be rejected");
        assert!(error.contains(&fixture), "{error}");
    }
}

fn assert_fact_runtime_symbols(evidence: &FactEvidence, expected: &[&str], contract_id: &str) {
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
                && carrier.path == "composition/eventing/src/lib.rs"
        }),
        "{contract_id} runtime carriers must be shared eventing-composition symbols"
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
    let generated_roles = evidence
        .generated
        .carriers
        .iter()
        .filter_map(|carrier| carrier.symbol.rsplit("::").next())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        generated_roles,
        BTreeSet::from(["PRODUCER", "SPEC"]),
        "{contract_id} generated carrier role projection drift"
    );
    assert_producer_evidence(evidence, contract_id, domain, emitted_facts);
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
                    vocab::ExternalEffectPolicy::TransactionalOnly => "transactional-only",
                    vocab::ExternalEffectPolicy::IdempotencyKey => "idempotency-key",
                    vocab::ExternalEffectPolicy::Reconcile => "reconcile",
                    vocab::ExternalEffectPolicy::Compensated => "compensated",
                },
            )
        })
        .collect();
    compiled_subscriptions.sort_unstable();
    assert_eq!(
        actual_subscriptions, compiled_subscriptions,
        "{contract_id}"
    );
    assert_complete_fact_evidence(evidence, contract_id);
}

#[allow(clippy::cognitive_complexity)]
fn assert_producer_evidence(
    evidence: &ProducerEvidence,
    contract_id: &str,
    domain: &str,
    emitted_facts: &[String],
) {
    for facet in [&evidence.contract, &evidence.generated] {
        assert_complete_facet(facet, contract_id);
    }
    assert_eq!(
        evidence.execution.status,
        FacetStatus::Complete,
        "{contract_id}"
    );
    assert_eq!(
        evidence.execution.route.kind,
        CarrierKind::RustSymbol,
        "{contract_id}"
    );
    assert!(
        evidence
            .execution
            .route
            .path
            .starts_with("generated/src/http/")
            && evidence.execution.route.symbol.ends_with("::SPEC"),
        "{contract_id} execution route must be its generated HTTP spec"
    );
    let handler = &evidence.execution.mounted_handler;
    assert_eq!(handler.kind, CarrierKind::RustSymbol, "{contract_id}");
    assert!(
        handler.path.starts_with(&format!("crates/{domain}/src/"))
            && handler.path.ends_with(".rs")
            && handler.symbol.ends_with("_handler"),
        "{contract_id} mounted handler drift"
    );
    let terminal_facts = evidence
        .execution
        .terminals
        .iter()
        .map(|terminal| terminal.fact_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        terminal_facts,
        emitted_facts.iter().map(String::as_str).collect::<Vec<_>>(),
        "{contract_id} terminal fact set must exactly equal emittedFacts"
    );
    for terminal in &evidence.execution.terminals {
        assert!(
            !terminal.domain_path.is_empty(),
            "{contract_id} has an empty domain execution path"
        );
        assert!(
            terminal.domain_path.iter().all(|carrier| {
                carrier.kind == CarrierKind::RustSymbol
                    && carrier.path.starts_with(&format!("crates/{domain}/src/"))
            }),
            "{contract_id} domain execution path escaped its domain"
        );
        assert!(
            terminal.port_method.path == format!("crates/{domain}/src/ports.rs")
                && terminal.port_method.symbol.contains("Local::"),
            "{contract_id} must record one exact local port method"
        );
        assert!(
            terminal
                .provider_method
                .path
                .starts_with("adapters/postgres/src/")
                && terminal.provider_method.symbol.starts_with("Pg")
                && terminal.provider_method.symbol.contains("::"),
            "{contract_id} must record one exact Postgres provider method"
        );
        assert!(
            terminal.production_composition.runtime_entry.path == "assemblies/runtime/src/phase.rs"
                && terminal.production_composition.runtime_entry.symbol == "execute"
                && terminal.production_composition.runtime_assembly.path
                    == "assemblies/runtime/src/phase/domains.rs"
                && terminal.production_composition.runtime_assembly.symbol
                    == "InfraBuilt::wire_domains"
                && terminal
                    .production_composition
                    .runtime_module
                    .path
                    .starts_with("assemblies/runtime/src/domains/")
                && terminal.production_composition.runtime_module.symbol == "module"
                && terminal
                    .production_composition
                    .wire
                    .path
                    .starts_with("composition/")
                && (terminal.production_composition.wire.symbol == "wire"
                    || (domain == "identity"
                        && terminal.production_composition.wire.symbol
                            == "common_identity_services"))
                && !terminal
                    .production_composition
                    .service_constructor
                    .is_empty()
                && !terminal.production_composition.provider_factory.is_empty(),
            "{contract_id} production composition is incomplete"
        );
        assert!(
            matches!(
                (
                    terminal.transaction.path.as_str(),
                    terminal.transaction.symbol.as_str(),
                ),
                (
                    "adapters/postgres/src/cotx/mod.rs",
                    "TenantDb::producer_tx" | "TenantDb::retry_producer_tx",
                ) | (
                    "adapters/postgres/src/cotx/settings_audit.rs",
                    "TenantDb::retry_config_producer_tx",
                )
            ),
            "{contract_id} transaction must use the only producer funnel"
        );
        assert_eq!(
            terminal.capability.kind,
            CarrierKind::RustType,
            "{contract_id}"
        );
        assert_eq!(
            terminal.capability.symbol, "TenantTx<'_, ServingWriteLane>",
            "{contract_id}"
        );
        assert_eq!(
            terminal.append.symbol, "append_outbox_with_projection",
            "{contract_id}"
        );
        assert_eq!(
            terminal.settlement.symbol, "finish_local_tx",
            "{contract_id}"
        );
        for carrier in terminal.domain_path.iter().chain([
            &terminal.port_method,
            &terminal.provider_method,
            &terminal.production_composition.runtime_entry,
            &terminal.production_composition.runtime_assembly,
            &terminal.production_composition.runtime_module,
            &terminal.production_composition.wire,
            &terminal.transaction,
            &terminal.capability,
            &terminal.append,
            &terminal.settlement,
        ]) {
            assert_canonical_repo_relative_path(&carrier.path, contract_id);
        }
    }
    assert_producer_fault(evidence, contract_id, emitted_facts);
}

fn assert_producer_fault(evidence: &ProducerEvidence, contract_id: &str, emitted_facts: &[String]) {
    let fault = &evidence.fault;
    assert_eq!(fault.status, FacetStatus::Complete, "{contract_id}");
    assert_eq!(
        fault
            .terminals
            .iter()
            .map(|terminal| terminal.fact_id.as_str())
            .collect::<Vec<_>>(),
        emitted_facts.iter().map(String::as_str).collect::<Vec<_>>(),
        "{contract_id} fault terminals must equal emitted facts"
    );
    for terminal in &fault.terminals {
        let execution = evidence
            .execution
            .terminals
            .iter()
            .find(|execution| execution.fact_id == terminal.fact_id)
            .unwrap_or_else(|| {
                panic!(
                    "{contract_id} fault terminal {} lacks execution terminal",
                    terminal.fact_id
                )
            });
        assert_eq!(
            terminal.provider_method, execution.provider_method,
            "{contract_id}/{} provider identity drift",
            terminal.fact_id
        );
        assert_eq!(
            terminal.transaction, execution.transaction,
            "{contract_id}/{} transaction identity drift",
            terminal.fact_id
        );
        assert!(
            matches!(
                (
                    terminal.transaction.path.as_str(),
                    terminal.transaction.symbol.as_str(),
                ),
                (
                    "adapters/postgres/src/cotx/mod.rs",
                    "TenantDb::producer_tx" | "TenantDb::retry_producer_tx",
                ) | (
                    "adapters/postgres/src/cotx/settings_audit.rs",
                    "TenantDb::retry_config_producer_tx",
                )
            ),
            "{contract_id}"
        );
        for (carrier, path, symbol) in [
            (
                &terminal.rollback,
                "adapters/postgres/src/cotx/mod.rs",
                "rollback_local_tx",
            ),
            (
                &terminal.commit_unknown,
                "adapters/postgres/src/cotx/mod.rs",
                "finish_local_tx_commit_result",
            ),
            (
                &terminal.rollback_failed,
                "adapters/postgres/src/cotx/mod.rs",
                "finish_local_tx_rollback_result",
            ),
        ] {
            assert_eq!(carrier.path, path, "{contract_id}");
            assert_eq!(carrier.symbol, symbol, "{contract_id}");
        }
        assert!(
            matches!(
                (
                    terminal.transaction.symbol.as_str(),
                    terminal.no_replay.path.as_str(),
                    terminal.no_replay.symbol.as_str(),
                ),
                (
                    "TenantDb::producer_tx",
                    "adapters/postgres/src/cotx/mod.rs",
                    "ProducerTxAttempt::into_result"
                        | "ProducerTxAttempt::into_refresh_commit_result",
                ) | (
                    "TenantDb::retry_producer_tx",
                    "adapters/postgres/src/cotx/settlement.rs",
                    "LocalTxAttempt::into_retry_result",
                ) | (
                    "TenantDb::retry_config_producer_tx",
                    "adapters/postgres/src/cotx/settlement.rs",
                    "LocalTxAttempt::into_retry_result",
                )
            ),
            "{contract_id} has a non-canonical settlement consumer: {:?}",
            terminal.no_replay
        );
    }
}

fn assert_complete_fact_evidence(evidence: &FactEvidence, contract_id: &str) {
    for facet in evidence.facets() {
        assert_complete_facet(facet, contract_id);
    }
    assert_fault_runner(&evidence.fault, contract_id);
    assert_required_inbox_security_scenarios(
        contract_id,
        evidence
            .fault
            .carriers
            .iter()
            .map(|carrier| (carrier.kind, carrier.symbol.as_str())),
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

fn assert_complete_facet(facet: &EvidenceFacet, contract_id: &str) {
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

fn assert_fault_runner(fault: &EvidenceFacet, contract_id: &str) {
    let runner_carriers = fault
        .carriers
        .iter()
        .filter(|carrier| carrier.kind == CarrierKind::RustSymbol)
        .collect::<Vec<_>>();
    assert!(
        !runner_carriers.is_empty(),
        "{contract_id} lacks fault runners"
    );
    let mut runner_symbols = BTreeSet::new();
    for carrier in &runner_carriers {
        assert!(
            runner_symbols.insert(carrier.symbol.as_str()),
            "{contract_id} duplicates fault runner {}",
            carrier.symbol
        );
        assert!(
            carrier.symbol.starts_with("run_") && carrier.symbol != "READY_CASE_RUNNERS",
            "{contract_id} has non-canonical fault runner {}",
            carrier.symbol
        );
    }
    assert!(
        fault
            .carriers
            .iter()
            .any(|carrier| carrier.kind == CarrierKind::FaultFixture),
        "{contract_id} lacks named fault fixtures"
    );
    assert!(
        runner_carriers.iter().all(|carrier| {
            carrier.path == "journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs"
        }),
        "{contract_id} fault runner escaped the dedicated journey"
    );
}

fn assert_required_inbox_security_scenarios<'a>(
    contract_id: &str,
    carriers: impl IntoIterator<Item = (CarrierKind, &'a str)>,
) -> Result<(), String> {
    if contract_id != "identity.session-created" {
        return Ok(());
    }

    let carriers = carriers.into_iter().collect::<Vec<_>>();
    assert_exact_ids(
        "identity.session-created required inbox security runners",
        REQUIRED_SESSION_CREATED_INBOX_SCENARIOS
            .into_iter()
            .map(str::to_owned),
        carriers
            .iter()
            .filter(|(kind, symbol)| {
                *kind == CarrierKind::RustSymbol && symbol.starts_with("run_inbox_")
            })
            .map(|(_, symbol)| (*symbol).to_owned()),
    )?;

    let required_fixtures = REQUIRED_SESSION_CREATED_INBOX_SCENARIOS
        .into_iter()
        .map(inbox_fixture_id);
    assert_exact_ids(
        "identity.session-created required inbox security fixture join",
        required_fixtures,
        carriers
            .iter()
            .filter(|(kind, symbol)| {
                *kind == CarrierKind::FaultFixture && symbol.starts_with("inbox-")
            })
            .map(|(_, symbol)| (*symbol).to_owned()),
    )
}

fn inbox_fixture_id(runner: &str) -> String {
    runner
        .strip_prefix("run_")
        .expect("required runner uses the run_ namespace")
        .replace('_', "-")
}

fn assert_exact_ids(
    label: &str,
    expected: impl IntoIterator<Item = String>,
    actual: impl IntoIterator<Item = String>,
) -> Result<(), String> {
    let expected = collect_unique_ids(label, "expected", expected)?;
    let actual = collect_unique_ids(label, "actual", actual)?;
    if expected == actual {
        return Ok(());
    }
    Err(format!(
        "{label} identity mismatch: missing={:?} extra={:?}",
        expected.difference(&actual).collect::<Vec<_>>(),
        actual.difference(&expected).collect::<Vec<_>>()
    ))
}

fn collect_unique_ids(
    label: &str,
    side: &str,
    identities: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>, String> {
    let mut unique = BTreeSet::new();
    for identity in identities {
        if !unique.insert(identity.clone()) {
            return Err(format!(
                "{label} {side} contains duplicate identity {identity}"
            ));
        }
    }
    Ok(unique)
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
