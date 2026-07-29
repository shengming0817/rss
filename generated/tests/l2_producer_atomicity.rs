#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

#[path = "support/l2_assurance.rs"]
mod l2_assurance_support;
use l2_assurance_support::{AssuranceInventory, AssuranceRecord, FacetStatus, ProducerEvidence};

const ASSURANCE_JSON: &str = include_str!("../l2-assurance.json");

#[test]
fn all_active_producers_have_one_closed_v3_execution_inventory() {
    let inventory =
        AssuranceInventory::parse_v3(ASSURANCE_JSON).expect("strict typed v3 inventory");
    assert_eq!(inventory.schema_version, 3);

    let producers = inventory
        .contracts
        .iter()
        .filter_map(|record| match record {
            AssuranceRecord::Producer {
                contract_id,
                emitted_facts,
                evidence,
                ..
            } => Some((contract_id, emitted_facts, evidence)),
            AssuranceRecord::Fact { .. } => None,
        })
        .collect::<Vec<_>>();
    assert!(!producers.is_empty(), "producer projection is empty");
    assert_eq!(producers.len(), inventory.producer_count);
    let producer_ids = producers
        .iter()
        .map(|(contract_id, _, _)| contract_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        producer_ids.len(),
        producers.len(),
        "producer identities must be unique"
    );

    for (contract_id, emitted_facts, evidence) in producers {
        assert_closed_execution(contract_id, emitted_facts, evidence);
    }

    assert!(!ASSURANCE_JSON.contains("co_tx_with_outbox"));
}

#[allow(clippy::cognitive_complexity)]
fn assert_closed_execution(
    contract_id: &str,
    emitted_facts: &[String],
    evidence: &ProducerEvidence,
) {
    assert_eq!(
        evidence.execution.status,
        FacetStatus::Complete,
        "{contract_id}"
    );
    assert!(
        evidence.execution.route.symbol.as_str().ends_with("::SPEC"),
        "{contract_id}"
    );
    assert!(
        evidence
            .execution
            .mounted_handler
            .symbol
            .as_str()
            .ends_with("_handler"),
        "{contract_id}"
    );

    let emitted = emitted_facts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let terminal_facts = evidence
        .execution
        .terminals
        .iter()
        .map(|terminal| terminal.fact_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        terminal_facts, emitted,
        "{contract_id} terminal set must exactly equal manifest/generated emits"
    );
    assert_eq!(
        evidence.fault.status,
        FacetStatus::Complete,
        "{contract_id}"
    );
    assert_eq!(
        evidence
            .fault
            .terminals
            .iter()
            .map(|terminal| terminal.fact_id.as_str())
            .collect::<BTreeSet<_>>(),
        emitted,
        "{contract_id} fault terminals must close the same fact set"
    );
    for fault in &evidence.fault.terminals {
        assert_eq!(
            fault.provider_method.path,
            evidence.execution.terminals[0].provider_method.path
        );
        assert_eq!(fault.transaction.path, "adapters/postgres/src/cotx/mod.rs");
        assert_eq!(fault.rollback.symbol, "rollback_local_tx");
        assert_eq!(fault.commit_unknown.symbol, "finish_local_tx_commit_result");
        assert_eq!(
            fault.rollback_failed.symbol,
            "finish_local_tx_rollback_result"
        );
        assert!(
            matches!(
                (
                    fault.transaction.symbol.as_str(),
                    fault.no_replay.symbol.as_str(),
                ),
                (
                    "PgWritePool::producer_tx",
                    "ProducerTxAttempt::into_result"
                        | "ProducerTxAttempt::into_refresh_commit_result",
                ) | (
                    "PgWritePool::retry_producer_tx",
                    "LocalTxAttempt::into_retry_result",
                )
            ),
            "{contract_id} has a non-canonical settlement consumer: {:?}",
            fault.no_replay
        );
    }

    for terminal in &evidence.execution.terminals {
        assert!(!terminal.domain_path.is_empty(), "{contract_id}");
        assert!(
            terminal.port_method.symbol.contains("Local::"),
            "{contract_id}"
        );
        assert!(
            terminal.provider_method.symbol.starts_with("Pg")
                && terminal.provider_method.symbol.contains("::"),
            "{contract_id}"
        );
        assert_eq!(terminal.capability.symbol, "TxCapability", "{contract_id}");
        assert_eq!(
            terminal.append.symbol, "append_outbox_with_projection",
            "{contract_id}"
        );
        assert_eq!(
            terminal.settlement.symbol, "finish_local_tx",
            "{contract_id}"
        );
        assert!(
            matches!(
                terminal.transaction.symbol.as_str(),
                "PgWritePool::producer_tx" | "PgWritePool::retry_producer_tx"
            ),
            "{contract_id}"
        );
    }
}
