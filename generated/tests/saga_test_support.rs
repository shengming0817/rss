#![cfg(feature = "test-support")]

use generated::saga::{SPECS, test_support};

#[test]
fn conformance_catalog_is_exact_and_excluded_from_production() {
    let fixture_ids = test_support::SPECS
        .iter()
        .map(|spec| spec.contract().contract_id())
        .collect::<Vec<_>>();
    assert_eq!(
        fixture_ids,
        [
            "test.saga-conformance.foreign",
            "test.saga-conformance.primary",
        ]
    );
    assert!(SPECS.iter().all(|spec| {
        !spec
            .contract()
            .contract_id()
            .starts_with("test.saga-conformance.")
    }));
}
