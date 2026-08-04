//! Settings secret publish LocalTx journey.

#[allow(dead_code)]
#[path = "support/localtx_validation.rs"]
mod support;

use anyhow::Result;
use support::{FixtureBook, FixtureIdentity, SettingsCases, drive_settings_journey};

const FIXTURE: &str = include_str!("../../fixtures/settings-secret-publish-localtx.toml");
const RUNNER: &str = "journeys/tests/settings_secret_publish_localtx_journey.rs";

#[tokio::test(flavor = "multi_thread")]
async fn settings_secret_publish_localtx_journey() -> Result<()> {
    const LOCALTX_JOURNEY_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    let _ = LOCALTX_JOURNEY_SETTINGS_SECRET_PUBLISH;

    let mut fixtures = FixtureBook::load(
        FIXTURE,
        FixtureIdentity {
            id: "settings-secret-publish-localtx",
            contract_id: generated::http::settings_v2::CONTRACT_ID,
            tx_model: "repo-atomic-cas",
            spec: "journeys/settings-secret-publish-localtx-journey.toml",
            runner: RUNNER,
            marker: "SETTINGS_SECRET_PUBLISH",
        },
    )?;
    let happy = fixtures.take_case("settings-secret-publish-happy")?;
    let auth_failure = fixtures.take_case("settings-secret-publish-auth-failure")?;
    let validation_failure = fixtures.take_case("settings-secret-publish-validation-failure")?;
    let conflict = fixtures.take_case("settings-secret-publish-conflict")?;
    let settings_cases = SettingsCases {
        happy,
        auth_failure,
        validation_failure,
        conflict,
    };
    drive_settings_journey(settings_cases).await?;
    fixtures.assert_exhausted()
}

#[test]
fn changed_fixture_behavior_is_observably_red() -> Result<()> {
    support::changed_fixture_behavior_is_observably_red()
}
