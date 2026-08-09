//! HTTP generated metadata contract tests.
//!
//! These tests lock the active runtime registry surface. Draft HTTP contracts may
//! use every consistency enum variant, but `generated::http::SPECS` stays
//! active-only.

use generated::http;
use std::collections::BTreeSet;
use vocab::{
    HttpConsistencyLevel, HttpEffectKind, LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel,
    LocalTxRetry,
};

const EXPECTED_LOCAL_TX_SPECS: &[(&str, LocalTxModel)] = &[
    ("audit.list-tenant-entries", LocalTxModel::TenantScopedUow),
    ("settings.secret-publish", LocalTxModel::RepoAtomicCas),
];

fn active_spec(contract_id: &str) -> Option<&'static http::HttpSpec> {
    http::SPECS
        .iter()
        .find(|spec| spec.route.contract_id() == contract_id)
}

fn assert_exact_ids(actual: &BTreeSet<&str>, expected: &BTreeSet<&str>, relation: &str) {
    let missing = expected.difference(actual).copied().collect::<Vec<_>>();
    let extra = actual.difference(expected).copied().collect::<Vec<_>>();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{relation}: missing={missing:?}, extra={extra:?}"
    );
}

#[test]
fn active_http_specs_expose_non_empty_effect_profiles() {
    let missing: Vec<_> = http::SPECS
        .iter()
        .filter(|spec| spec.route.effect_profile().effects().is_empty())
        .map(|spec| spec.route.contract_id())
        .collect();
    assert!(
        missing.is_empty(),
        "every active HTTP spec must expose non-empty effect metadata: {missing:?}"
    );
}

#[test]
fn audit_reads_expose_split_effect_profiles() {
    let scoped: &[HttpEffectKind] =
        active_spec("audit.list-entries").map_or(&[], |spec| spec.route.effect_profile().effects());
    assert_eq!(
        scoped,
        &[
            HttpEffectKind::Auth,
            HttpEffectKind::Read,
            HttpEffectKind::Projection
        ]
    );

    let target: &[HttpEffectKind] = active_spec("audit.list-tenant-entries")
        .map_or(&[], |spec| spec.route.effect_profile().effects());
    assert_eq!(
        target,
        &[
            HttpEffectKind::Auth,
            HttpEffectKind::Read,
            HttpEffectKind::Projection,
            HttpEffectKind::BusinessWrite,
            HttpEffectKind::BusinessTransaction,
            HttpEffectKind::CrossTenantAudit,
        ]
    );
}

#[test]
fn audit_list_entries_declares_complete_typed_response_set() {
    use generated::http::HttpResponseBinding as _;
    use generated::http::audit_v1::list_entries::{
        AuditListEntriesBadRequestResponse, AuditListEntriesInternalServerErrorResponse,
        AuditListEntriesResponse, RESPONSES,
    };

    assert_eq!(AuditListEntriesResponse::STATUS, 200);
    assert_eq!(AuditListEntriesBadRequestResponse::STATUS, 400);
    assert_eq!(AuditListEntriesInternalServerErrorResponse::STATUS, 500);
    assert_eq!(
        RESPONSES
            .iter()
            .map(|response| response.status)
            .collect::<Vec<_>>(),
        [200, 400, 500]
    );
}

#[test]
fn local_tx_registry_contains_exact_active_l1_contracts() {
    let actual: Option<Vec<_>> = http::LOCAL_TX_SPECS
        .iter()
        .map(|spec| {
            spec.local_tx
                .map(|evidence| (spec.route.contract_id(), evidence.tx_model))
        })
        .collect();
    assert!(
        actual.is_some(),
        "every LocalTx registry entry should carry LocalTx evidence"
    );
    let actual = actual.unwrap_or_default();
    let from_specs: BTreeSet<_> = http::SPECS
        .iter()
        .filter(|spec| spec.route.consistency_level() == HttpConsistencyLevel::LocalTx)
        .map(|spec| spec.route.contract_id())
        .collect();
    assert_eq!(
        actual.as_slice(),
        EXPECTED_LOCAL_TX_SPECS,
        "LOCAL_TX_SPECS should expose the current active L1 contract set"
    );
    let local_tx_ids = actual
        .iter()
        .map(|(contract_id, _)| *contract_id)
        .collect::<BTreeSet<_>>();
    assert_exact_ids(
        &local_tx_ids,
        &from_specs,
        "LOCAL_TX_SPECS must be the exact stable-ID projection of active LocalTx HTTP specs",
    );
    assert_eq!(
        local_tx_ids.len(),
        http::LOCAL_TX_SPECS.len(),
        "LOCAL_TX_SPECS must not contain duplicates"
    );
    for spec in http::LOCAL_TX_SPECS {
        assert!(
            spec.local_tx.is_some(),
            "every LocalTx registry entry should carry LocalTx evidence"
        );
        let Some(evidence) = spec.local_tx else {
            continue;
        };
        assert_eq!(
            spec.route.consistency_level(),
            HttpConsistencyLevel::LocalTx
        );
        assert_eq!(evidence.boundary, LocalTxBoundary::SingleDomain);
        assert_eq!(evidence.retry, LocalTxRetry::BoundedTransient);
        assert_eq!(evidence.commit_unknown, LocalTxCommitUnknown::NotRetryable);
    }

    for spec in http::SPECS {
        assert_eq!(
            spec.local_tx.is_some(),
            spec.route.consistency_level() == HttpConsistencyLevel::LocalTx,
            "local_tx evidence should only be present on LocalTx specs: {}",
            spec.route.contract_id()
        );
    }
}

#[test]
fn local_only_registry_contains_exact_active_l0_contracts() {
    let actual: BTreeSet<_> = http::LOCAL_ONLY_SPECS
        .iter()
        .map(|spec| spec.route.contract_id())
        .collect();
    let from_specs: BTreeSet<_> = http::SPECS
        .iter()
        .filter(|spec| spec.route.consistency_level() == HttpConsistencyLevel::LocalOnly)
        .map(|spec| spec.route.contract_id())
        .collect();

    assert_exact_ids(
        &actual,
        &from_specs,
        "LOCAL_ONLY_SPECS must be the exact stable-ID projection of active LocalOnly HTTP specs",
    );
    assert_eq!(
        actual.len(),
        http::LOCAL_ONLY_SPECS.len(),
        "LOCAL_ONLY_SPECS must not contain duplicates"
    );
    assert!(http::LOCAL_ONLY_SPECS.iter().all(|spec| {
        spec.route.consistency_level() == HttpConsistencyLevel::LocalOnly && spec.local_tx.is_none()
    }));
}

#[test]
fn local_tx_specs_reuse_required_module_evidence() {
    let contracts = [
        (
            http::audit_v1::list_tenant_entries::SPEC,
            http::audit_v1::list_tenant_entries::LOCAL_TX,
        ),
        (http::settings_v2::SPEC, http::settings_v2::LOCAL_TX),
    ];

    for (spec, evidence) in contracts {
        assert_eq!(
            spec.local_tx,
            Some(evidence),
            "{} must reuse its non-optional module LocalTx evidence",
            spec.route.contract_id()
        );
    }
}

#[test]
fn identity_security_routes_expose_outbox_producer_evidence() {
    let producers = [
        http::identity_v1::account_status_set::PRODUCER.evidence(),
        http::identity_v1::password_change::PRODUCER.evidence(),
    ];

    for producer in producers {
        assert_eq!(
            producer.route().consistency_level(),
            HttpConsistencyLevel::OutboxFact
        );
        assert_eq!(producer.emitted_facts().len(), 1);
        assert_eq!(
            producer.emitted_facts()[0].contract_id(),
            "identity.security-event"
        );
        assert!(http::OUTBOX_PRODUCERS.contains(&producer));
    }
}

#[test]
fn active_http_registry_has_unique_stable_ids() {
    assert!(
        !http::SPECS.is_empty(),
        "active HTTP registry must not be empty"
    );
    let ids = http::SPECS
        .iter()
        .map(|spec| spec.route.contract_id())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        http::SPECS.len(),
        "active HTTP contract IDs must be unique"
    );
}
