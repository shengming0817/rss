//! Identity logout LocalTx journey.

#![cfg(feature = "integration")]

#[allow(dead_code)]
#[path = "support/localtx_validation.rs"]
mod support;

use anyhow::Result;
use support::{FixtureBook, FixtureIdentity, LogoutCases, drive_logout_journey};

const FIXTURE: &str = include_str!("../../fixtures/identity-logout-localtx.toml");
const RUNNER: &str = "journeys/tests/identity_logout_localtx_journey.rs";

#[tokio::test(flavor = "multi_thread")]
async fn identity_logout_localtx_journey() -> Result<()> {
    const LOCALTX_JOURNEY_IDENTITY_LOGOUT: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::logout::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::identity_v1::logout::ROUTE;
    let _ = LOCALTX_JOURNEY_IDENTITY_LOGOUT;

    let mut fixtures = FixtureBook::load(
        FIXTURE,
        FixtureIdentity {
            id: "identity-logout-localtx",
            contract_id: generated::http::identity_v1::logout::CONTRACT_ID,
            tx_model: "tenant-scoped-uow",
            spec: "journeys/identity-logout-localtx-journey.toml",
            runner: RUNNER,
            marker: "IDENTITY_LOGOUT",
        },
    )?;
    let happy = fixtures.take_case("identity-logout-happy")?;
    let unauthenticated = fixtures.take_case("identity-logout-unauthenticated")?;
    let other_owner = fixtures.take_case("identity-logout-other-owner")?;
    let validation_failure = fixtures.take_case("identity-logout-validation-failure")?;
    let contention = fixtures.take_case("identity-logout-contention")?;
    let repeat = fixtures.take_case("identity-logout-repeat")?;
    let cross_tenant = fixtures.take_case("identity-logout-cross-tenant")?;
    let logout_cases = LogoutCases {
        happy,
        unauthenticated,
        other_owner,
        validation_failure,
        contention,
        repeat,
        cross_tenant,
    };
    drive_logout_journey(logout_cases).await?;
    fixtures.assert_exhausted()
}
