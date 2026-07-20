//! Provider capability catalog contract and compile-fail tests for #1827.

use testkit::eventing_conformance::{CapabilityId, ProviderId};

#[test]
fn provider_capability_catalog_is_closed_and_provider_specific() {
    assert_eq!(
        CapabilityId::ALL.map(CapabilityId::as_str),
        [
            "identity",
            "conflict",
            "fencing",
            "budget",
            "commit-ack",
            "ambiguity",
            "archive-receipt",
        ]
    );
    assert_eq!(
        ProviderId::Postgres
            .capabilities()
            .iter()
            .copied()
            .map(CapabilityId::as_str)
            .collect::<Vec<_>>(),
        CapabilityId::ALL.map(CapabilityId::as_str)
    );
    assert_eq!(
        ProviderId::Amqp.capabilities(),
        &[
            CapabilityId::Identity,
            CapabilityId::Fencing,
            CapabilityId::Budget,
            CapabilityId::Ambiguity,
        ]
    );
    assert_eq!(
        ProviderId::S3.capabilities(),
        &[
            CapabilityId::Identity,
            CapabilityId::Conflict,
            CapabilityId::ArchiveReceipt,
        ]
    );
}

#[test]
fn provider_catalog_type_and_breaking_syntax_compile_reds() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/provider_catalog_*.rs");
}
