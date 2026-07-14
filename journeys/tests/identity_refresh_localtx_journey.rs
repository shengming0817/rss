//! Identity refresh LocalTx journey.

#![cfg(feature = "integration")]

#[allow(dead_code)]
#[path = "support/localtx_validation.rs"]
mod support;

use anyhow::Result;
use support::{FixtureBook, FixtureIdentity, RefreshCases, drive_refresh_journey};

const FIXTURE: &str = include_str!("../../fixtures/identity-refresh-localtx.toml");
const RUNNER: &str = "journeys/tests/identity_refresh_localtx_journey.rs";

#[tokio::test(flavor = "multi_thread")]
async fn identity_refresh_localtx_journey() -> Result<()> {
    const LOCALTX_JOURNEY_IDENTITY_REFRESH: ::vocab::HttpRouteBinding<
        ::generated::http::identity_v1::refresh::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::identity_v1::refresh::ROUTE;
    let _ = LOCALTX_JOURNEY_IDENTITY_REFRESH;

    let mut fixtures = FixtureBook::load(
        FIXTURE,
        FixtureIdentity {
            id: "identity-refresh-localtx",
            contract_id: generated::http::identity_v1::refresh::CONTRACT_ID,
            tx_model: "tenant-scoped-uow",
            spec: "journeys/identity-refresh-localtx-journey.toml",
            runner: RUNNER,
            marker: "IDENTITY_REFRESH",
        },
    )?;
    let happy = fixtures.take_case("identity-refresh-happy")?;
    let unknown = fixtures.take_case("identity-refresh-unknown")?;
    let malformed = fixtures.take_case("identity-refresh-malformed")?;
    let contention_winner = fixtures.take_case("identity-refresh-contention-winner")?;
    let contention_loser = fixtures.take_case("identity-refresh-contention-loser")?;
    let commit_unknown = fixtures.take_case("identity-refresh-commit-unknown")?;
    let refresh_cases = RefreshCases {
        happy,
        unknown,
        malformed,
        contention_winner,
        contention_loser,
        commit_unknown,
    };
    drive_refresh_journey(refresh_cases).await?;
    fixtures.assert_exhausted()
}
