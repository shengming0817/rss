//! HTTP generated metadata contract tests.
//!
//! These tests lock the active runtime registry surface. Draft HTTP contracts may
//! use every consistency enum variant, but `generated::http::SPECS` stays
//! active-only.

use generated::http::{self, HttpConsistencyLevel};

const EXPECTED_ACTIVE_SPECS: &[(&str, HttpConsistencyLevel)] = &[
    ("audit.list-entries", HttpConsistencyLevel::LocalOnly),
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
    ("settings.config-publish", HttpConsistencyLevel::OutboxFact),
    ("settings.secret-publish", HttpConsistencyLevel::LocalTx),
];

fn count_in_registry(level: HttpConsistencyLevel) -> usize {
    http::SPECS
        .iter()
        .filter(|spec| spec.consistency_level == level)
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
fn active_http_specs_expose_manifest_consistency_levels() {
    for (contract_id, expected) in EXPECTED_ACTIVE_SPECS {
        let actual = http::SPECS
            .iter()
            .find(|spec| spec.contract_id == *contract_id)
            .map(|spec| spec.consistency_level);
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
                .any(|(contract_id, _)| *contract_id == spec.contract_id)
        })
        .map(|spec| spec.contract_id)
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
            (HttpConsistencyLevel::LocalOnly, 5),
            (HttpConsistencyLevel::LocalTx, 4),
            (HttpConsistencyLevel::OutboxFact, 7),
            (HttpConsistencyLevel::WorkflowEventual, 0),
            (HttpConsistencyLevel::DeviceLatent, 0),
        ],
        "active HTTP consistency distribution drifted; per-contract expectations identify the changed spec"
    );
}
