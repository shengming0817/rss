//! Audit target-tenant list LocalTx journey.

#![cfg(feature = "integration")]

#[allow(dead_code)]
#[path = "support/localtx_validation.rs"]
mod support;

use anyhow::Result;
use support::{AuditCases, FixtureBook, FixtureIdentity, drive_audit_journey};

const FIXTURE: &str = include_str!("../../fixtures/audit-list-tenant-entries-localtx.toml");
const RUNNER: &str = "journeys/tests/audit_list_tenant_entries_localtx_journey.rs";

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_tenant_entries_localtx_journey() -> Result<()> {
    const LOCALTX_JOURNEY_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
        ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
    let _ = LOCALTX_JOURNEY_AUDIT_LIST_TENANT_ENTRIES;

    let mut fixtures = FixtureBook::load(
        FIXTURE,
        FixtureIdentity {
            id: "audit-list-tenant-entries-localtx",
            contract_id: generated::http::audit_v1::list_tenant_entries::CONTRACT_ID,
            tx_model: "tenant-scoped-uow",
            spec: "journeys/audit-list-tenant-entries-localtx-journey.toml",
            runner: RUNNER,
            marker: "AUDIT_LIST_TENANT_ENTRIES",
        },
    )?;
    let happy = fixtures.take_case("audit-list-tenant-entries-happy")?;
    let unauthenticated = fixtures.take_case("audit-list-tenant-entries-unauthenticated")?;
    let non_superadmin_deny =
        fixtures.take_case("audit-list-tenant-entries-non-superadmin-deny")?;
    let validation = fixtures.take_case("audit-list-tenant-entries-validation")?;
    let contention = fixtures.take_case("audit-list-tenant-entries-contention")?;
    let audit_cases = AuditCases {
        happy,
        unauthenticated,
        non_superadmin_deny,
        validation,
        contention,
    };
    drive_audit_journey(audit_cases).await?;
    fixtures.assert_exhausted()
}
