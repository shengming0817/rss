//! Identity password-change LocalTx journey.

#![cfg(feature = "integration")]

#[allow(dead_code)]
#[path = "support/localtx_validation.rs"]
mod support;

use anyhow::Result;
use support::{FixtureBook, FixtureIdentity, PasswordCases, drive_password_journey};

const FIXTURE: &str = include_str!("../../fixtures/identity-password-change-localtx.toml");
const RUNNER: &str = "journeys/tests/identity_password_change_localtx_journey.rs";

#[tokio::test(flavor = "multi_thread")]
async fn identity_password_change_localtx_journey() -> Result<()> {
    const LOCALTX_JOURNEY_IDENTITY_PASSWORD_CHANGE: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::password_change::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::identity_v1::password_change::ROUTE;
    let _ = LOCALTX_JOURNEY_IDENTITY_PASSWORD_CHANGE;

    let mut fixtures = FixtureBook::load(
        FIXTURE,
        FixtureIdentity {
            id: "identity-password-change-localtx",
            contract_id: generated::http::identity_v1::password_change::CONTRACT_ID,
            tx_model: "repo-atomic-cas",
            spec: "journeys/identity-password-change-localtx-journey.toml",
            runner: RUNNER,
            marker: "IDENTITY_PASSWORD_CHANGE",
        },
    )?;
    let happy = fixtures.take_case("identity-password-change-happy")?;
    let unauthenticated = fixtures.take_case("identity-password-change-unauthenticated")?;
    let invalid_subject = fixtures.take_case("identity-password-change-invalid-subject")?;
    let validation_failure = fixtures.take_case("identity-password-change-validation-failure")?;
    let conflict = fixtures.take_case("identity-password-change-conflict")?;
    let password_cases = PasswordCases {
        happy,
        unauthenticated,
        invalid_subject,
        validation_failure,
        conflict,
    };
    drive_password_journey(password_cases).await?;
    fixtures.assert_exhausted()
}
