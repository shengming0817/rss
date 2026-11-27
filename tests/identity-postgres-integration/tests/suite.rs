//! Exercise Identity and its caller-owned transaction with the real role and provider.
use rss_audit_postgres::Integrity;
use rss_ledger::{Authenticator, KeyId};
use std::sync::Arc;
#[path = "support/federation.rs"]
mod federation_support;
mod support;
mod cases {
    pub mod federation;
    pub mod one_time;
    pub mod provisioning;
    pub mod roles;
    pub mod sessions;
    pub mod transactions;
    pub mod web_credentials;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_postgres() -> anyhow::Result<()> {
    let network = testkit::bridge_network("identity-postgres").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "identity-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let f = support::Fixture::new(&pg, Integrity::Plain).await?;
    f.bootstrap().await?;
    cases::roles::roles(&f).await?;
    cases::sessions::rotation(&f).await?;
    cases::web_credentials::run(&f).await?;
    cases::transactions::borrowed(&f).await?;
    cases::one_time::webauthn(&f).await?;
    cases::federation::state_once(&f).await?;
    f.close().await;
    let f = support::Fixture::new(&pg, Integrity::Plain).await?;
    f.bootstrap().await?;
    cases::federation::step_up(&f).await?;
    cases::provisioning::provisioning(&f).await?;
    f.close().await;
    let ledger = Integrity::Ledger(Arc::new(Authenticator::new(
        KeyId::parse("identity-fixture")?,
        vec![7; 32],
    )?));
    let f = support::Fixture::new(&pg, ledger).await?;
    f.bootstrap().await?;
    cases::sessions::audit_settlement(&f).await?;
    f.close().await;
    Ok(())
}
