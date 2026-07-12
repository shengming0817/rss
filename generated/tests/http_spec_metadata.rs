//! HTTP generated metadata contract tests.
//!
//! These tests lock the active runtime registry surface. Draft HTTP contracts may
//! use every consistency enum variant, but `generated::http::SPECS` stays
//! active-only.

use generated::http;
use vocab::{
    HttpConsistencyLevel, HttpEffectKind, LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel,
    LocalTxRetry,
};

const EXPECTED_ACTIVE_SPECS: &[(&str, HttpConsistencyLevel)] = &[
    ("audit.list-entries", HttpConsistencyLevel::LocalOnly),
    ("audit.list-tenant-entries", HttpConsistencyLevel::LocalTx),
    ("identity.login", HttpConsistencyLevel::OutboxFact),
    ("identity.logout", HttpConsistencyLevel::LocalTx),
    ("identity.password-change", HttpConsistencyLevel::LocalTx),
    ("identity.policies-create", HttpConsistencyLevel::OutboxFact),
    (
        "identity.policies-deactivate",
        HttpConsistencyLevel::OutboxFact,
    ),
    ("identity.policies-get", HttpConsistencyLevel::LocalOnly),
    ("identity.policies-list", HttpConsistencyLevel::LocalOnly),
    ("identity.policies-update", HttpConsistencyLevel::OutboxFact),
    ("identity.profile", HttpConsistencyLevel::LocalOnly),
    ("identity.refresh", HttpConsistencyLevel::LocalTx),
    ("identity.roles-assign", HttpConsistencyLevel::OutboxFact),
    ("identity.roles-list", HttpConsistencyLevel::LocalOnly),
    ("identity.roles-revoke", HttpConsistencyLevel::OutboxFact),
    ("settings.config-get", HttpConsistencyLevel::LocalOnly),
    ("settings.config-delete", HttpConsistencyLevel::OutboxFact),
    ("settings.config-publish", HttpConsistencyLevel::OutboxFact),
    ("settings.config-rollback", HttpConsistencyLevel::OutboxFact),
    ("settings.secret-publish", HttpConsistencyLevel::LocalTx),
];

const EXPECTED_LOCAL_TX_SPECS: &[(&str, LocalTxModel)] = &[
    ("audit.list-tenant-entries", LocalTxModel::TenantScopedUow),
    ("identity.logout", LocalTxModel::TenantScopedUow),
    ("identity.password-change", LocalTxModel::TenantScopedUow),
    ("identity.refresh", LocalTxModel::TenantScopedUow),
    ("settings.secret-publish", LocalTxModel::RepoAtomicCas),
];

fn active_spec(contract_id: &str) -> Option<&'static http::HttpSpec> {
    http::SPECS
        .iter()
        .find(|spec| spec.route.contract_id() == contract_id)
}

fn count_in_registry(level: HttpConsistencyLevel) -> usize {
    http::SPECS
        .iter()
        .filter(|spec| spec.route.consistency_level() == level)
        .count()
}

fn registry_distribution() -> [(HttpConsistencyLevel, usize); 5] {
    [
        (
            HttpConsistencyLevel::LocalOnly,
            count_in_registry(HttpConsistencyLevel::LocalOnly),
        ),
        (
            HttpConsistencyLevel::LocalTx,
            count_in_registry(HttpConsistencyLevel::LocalTx),
        ),
        (
            HttpConsistencyLevel::OutboxFact,
            count_in_registry(HttpConsistencyLevel::OutboxFact),
        ),
        (
            HttpConsistencyLevel::WorkflowEventual,
            count_in_registry(HttpConsistencyLevel::WorkflowEventual),
        ),
        (
            HttpConsistencyLevel::DeviceLatent,
            count_in_registry(HttpConsistencyLevel::DeviceLatent),
        ),
    ]
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
            HttpEffectKind::Write,
            HttpEffectKind::Transaction,
            HttpEffectKind::CrossTenantAudit,
        ]
    );
}

#[test]
fn local_tx_registry_contains_exact_active_l1_contracts() {
    let actual: Vec<_> = http::LOCAL_TX_SPECS
        .iter()
        .map(|spec| {
            (
                spec.route.contract_id(),
                spec.local_tx
                    .expect("every LocalTx registry entry should carry LocalTx evidence")
                    .tx_model,
            )
        })
        .collect();
    let from_specs: Vec<_> = http::SPECS
        .iter()
        .filter(|spec| spec.route.consistency_level() == HttpConsistencyLevel::LocalTx)
        .map(|spec| spec.route.contract_id())
        .collect();
    assert_eq!(
        actual.as_slice(),
        EXPECTED_LOCAL_TX_SPECS,
        "LOCAL_TX_SPECS should expose the current active L1 contract set"
    );
    assert_eq!(
        actual
            .iter()
            .map(|(contract_id, _)| *contract_id)
            .collect::<Vec<_>>(),
        from_specs,
        "LOCAL_TX_SPECS should be derived from active LocalTx HTTP specs"
    );
    for spec in http::LOCAL_TX_SPECS {
        let evidence = spec
            .local_tx
            .expect("every LocalTx registry entry should carry LocalTx evidence");
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
fn active_http_specs_expose_manifest_consistency_levels() {
    for (contract_id, expected) in EXPECTED_ACTIVE_SPECS {
        let actual = http::SPECS
            .iter()
            .find(|spec| spec.route.contract_id() == *contract_id)
            .map(|spec| spec.route.consistency_level());
        assert_eq!(
            actual,
            Some(*expected),
            "active HTTP spec {contract_id} missing or consistency level drifted"
        );
    }

    let unexpected: Vec<_> = http::SPECS
        .iter()
        .filter(|spec| {
            !EXPECTED_ACTIVE_SPECS
                .iter()
                .any(|(contract_id, _)| *contract_id == spec.route.contract_id())
        })
        .map(|spec| spec.route.contract_id())
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected active HTTP specs in root SPECS: {unexpected:?}"
    );
}

#[test]
fn active_http_registry_keeps_current_consistency_distribution() {
    assert_eq!(
        http::SPECS.len(),
        EXPECTED_ACTIVE_SPECS.len(),
        "only active HTTP specs enter root SPECS"
    );
    assert_eq!(
        registry_distribution(),
        [
            (HttpConsistencyLevel::LocalOnly, 6),
            (HttpConsistencyLevel::LocalTx, 5),
            (HttpConsistencyLevel::OutboxFact, 9),
            (HttpConsistencyLevel::WorkflowEventual, 0),
            (HttpConsistencyLevel::DeviceLatent, 0),
        ],
        "active HTTP consistency distribution drifted; per-contract expectations identify the changed spec"
    );
}
